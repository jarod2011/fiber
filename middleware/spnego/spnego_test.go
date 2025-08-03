package spnego

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func ExampleNewSpnegoKrb5AuthenticateMiddleware() {
	app := fiber.New()
	keytabLookup, err := NewKeytabFileLookupFunc("/keytabFile/one.keytab", "/keytabFile/two.keyta")
	if err != nil {
		panic(fmt.Errorf("create keytab lookup function failed: %w", err))
	}
	authMiddleware, err := NewSpnegoKrb5AuthenticateMiddleware(&Config{
		KeytabLookup: keytabLookup,
	})
	if err != nil {
		panic(fmt.Errorf("create spnego middleware failed: %w", err))
	}
	// Apply the middleware to protected routes
	app.Use("/protected", authMiddleware)

	// Access authenticated identity
	app.Get("/protected/resource", func(c fiber.Ctx) error {
		identity, ok := GetAuthenticatedIdentityFromContext(c)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		return c.SendString(fmt.Sprintf("Hello, %s!", identity.UserName()))
	})

	app.Listen(":3000")
}

func TestNewSpnegoKrb5AuthenticateMiddleware(t *testing.T) {
	t.Parallel()
	t.Run("test for keytab lookup function not set", func(t *testing.T) {
		_, err := NewSpnegoKrb5AuthenticateMiddleware(&Config{})
		assert.ErrorIs(t, err, ErrConfigInvalidOfKeytabLookupFunctionRequired)
	})
	t.Run("test for keytab lookup failed", func(t *testing.T) {
		middleware, err := NewSpnegoKrb5AuthenticateMiddleware(&Config{
			KeytabLookup: func() (*keytab.Keytab, error) {
				return nil, errors.New("mock keytab lookup error")
			},
		})
		assert.Nil(t, err)
		app := fiber.New()
		app.Get("/authenticate", middleware, func(c fiber.Ctx) error {
			return c.SendString("authenticated")
		})
		handler := app.Handler()
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fiber.MethodGet)
		ctx.Request.SetRequestURI("/authenticate")
		handler(ctx)
		require.Equal(t, http.StatusInternalServerError, ctx.Response.StatusCode())
		require.Equal(t, fmt.Sprintf("%s: mock keytab lookup error", ErrLookupKeytabFailed), string(ctx.Response.Body()))
	})
	t.Run("test for keytab lookup function is set", func(t *testing.T) {
		var keytabFiles []string
		for i := 0; i < 5; i++ {
			kt, clean, err := newKeytabTempFile(fmt.Sprintf("HTTP/sso%d.example.com", i), "KRB5.TEST", 18, 19)
			assert.Nil(t, err)
			t.Cleanup(clean)
			keytabFiles = append(keytabFiles, kt)
		}
		lookupFunc, err := NewKeytabFileLookupFunc(keytabFiles...)
		assert.Nil(t, err)
		middleware, err := NewSpnegoKrb5AuthenticateMiddleware(&Config{
			KeytabLookup: lookupFunc,
		})
		assert.Nil(t, err)
		app := fiber.New()
		app.Get("/authenticate", middleware, func(c fiber.Ctx) error {
			user, ok := GetAuthenticatedIdentityFromContext(c)
			if ok {
				t.Logf("username: %s\ndomain: %s\n", user.UserName(), user.Domain())
			}
			return c.SendString("authenticated")
		})
		handler := app.Handler()
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fiber.MethodGet)
		ctx.Request.SetRequestURI("/authenticate")
		handler(ctx)
		require.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
		fmt.Println(ctx.Response.Header.String())
	})
}

func TestNewKeytabFileLookupFunc(t *testing.T) {
	t.Run("test for empty keytab files", func(t *testing.T) {
		_, err := NewKeytabFileLookupFunc()
		assert.ErrorIs(t, err, ErrConfigInvalidOfAtLeastOneKeytabFileRequired)
	})
	t.Run("test for has invalid keytab file", func(t *testing.T) {
		kt1, clean, err := newKeytabTempFile("HTTP/sso.example.com", "KRB5.TEST", 18, 19)
		assert.Nil(t, err)
		t.Cleanup(clean)
		kt2, clean, err := newBadKeytabTempFile("HTTP/sso1.example.com", "KRB5.TEST", 18, 19)
		assert.Nil(t, err)
		t.Cleanup(clean)
		_, err = NewKeytabFileLookupFunc(kt1, kt2)
		assert.ErrorIs(t, err, ErrLoadKeytabFileFailed)
	})
	t.Run("test for some keytab files", func(t *testing.T) {
		var keytabFiles []string
		for i := 0; i < 5; i++ {
			kt, clean, err := newKeytabTempFile(fmt.Sprintf("HTTP/sso%d.example.com", i), "KRB5.TEST", 18, 19)
			assert.Nil(t, err)
			t.Cleanup(clean)
			keytabFiles = append(keytabFiles, kt)
		}
		lookupFunc, err := NewKeytabFileLookupFunc(keytabFiles...)
		assert.Nil(t, err)
		_, err = lookupFunc()
		assert.Nil(t, err)
	})
}

func newBadKeytabTempFile(principal string, realm string, et ...int32) (filename string, clean func(), err error) {
	filename = fmt.Sprintf("./tmp_%d.keytab", time.Now().Unix())
	clean = func() {
		os.Remove(filename)
	}
	var kt keytab.Keytab
	for _, e := range et {
		kt.AddEntry(principal, realm, "abcdefg", time.Now(), 2, e)
	}
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		return filename, clean, fmt.Errorf("open file failed: %w", err)
	}
	if _, err = kt.Write(file); err != nil {
		return filename, clean, fmt.Errorf("write file failed: %w", err)
	}
	file.Close()
	return filename, clean, nil
}

func newKeytabTempFile(principal string, realm string, et ...int32) (filename string, clean func(), err error) {
	filename = fmt.Sprintf("./tmp_%d.keytab", time.Now().Unix())
	clean = func() {
		os.Remove(filename)
	}
	kt := keytab.New()
	for _, e := range et {
		kt.AddEntry(principal, realm, "abcdefg", time.Now(), 2, e)
	}
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		return filename, clean, fmt.Errorf("open file failed: %w", err)
	}
	if _, err = kt.Write(file); err != nil {
		return filename, clean, fmt.Errorf("write file failed: %w", err)
	}
	file.Close()
	return filename, clean, nil
}
