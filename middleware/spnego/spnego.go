// Package spnego provides SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism)
// authentication middleware for Fiber applications.
// This file contains the main middleware implementation and related functions.
package spnego

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v3"
	flog "github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// NewSpnegoKrb5AuthenticateMiddleware creates a new SPNEGO authentication middleware
// It takes a Config struct and returns a Fiber handler or an error
// The middleware handles Kerberos authentication for incoming requests
func NewSpnegoKrb5AuthenticateMiddleware(cfg *Config) (fiber.Handler, error) {
	// Validate configuration
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.KeytabLookup == nil {
		return nil, ErrConfigInvalidOfKeytabLookupFunctionRequired
	}
	// Set default logger if not provided
	if cfg.Log == nil {
		cfg.Log = flog.DefaultLogger().Logger().(*log.Logger)
	}
	// Return the middleware handler
	return func(ctx fiber.Ctx) error {
		// Look up the keytab
		kt, err := cfg.KeytabLookup()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLookupKeytabFailed, err)
		}
		// Create the SPNEGO handler using the keytab
		var handleErr error
		handler := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			// Set the authenticated identity in the Fiber context
			setAuthenticatedIdentityToContext(ctx, goidentity.FromHTTPRequestContext(r))
			// Call the next handler in the chain
			handleErr = ctx.Next()
		}), kt, service.Logger(cfg.Log))
		// Convert Fiber context to HTTP request
		rawReq, err := adaptor.ConvertRequest(ctx, true)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrConvertRequestFailed, err)
		}
		// Serve the request using the SPNEGO handler
		handler.ServeHTTP(wrapCtx{ctx}, rawReq)
		return handleErr
	}, nil
}

// contextKeyOfIdentity is the key used to store the authenticated identity in the Fiber context
const contextKeyOfIdentity = "middleware.spnego.Identity"

// setAuthenticatedIdentityToContext stores the authenticated identity in the Fiber context
// It takes a Fiber context and an identity, and sets it using the contextKeyOfIdentity key
func setAuthenticatedIdentityToContext(ctx fiber.Ctx, identity goidentity.Identity) {
	ctx.Locals(contextKeyOfIdentity, identity)
}

// GetAuthenticatedIdentityFromContext retrieves the authenticated identity from the Fiber context
// It returns the identity and a boolean indicating if it was found
func GetAuthenticatedIdentityFromContext(ctx fiber.Ctx) (goidentity.Identity, bool) {
	id, ok := ctx.Locals(contextKeyOfIdentity).(goidentity.Identity)
	return id, ok
}

// wrapCtx wraps a Fiber context to implement the http.ResponseWriter interface
// This allows the Fiber context to be used with the standard HTTP handler

type wrapCtx struct {
	fiber.Ctx
}

// Header returns the request headers from the wrapped Fiber context
func (w wrapCtx) Header() http.Header {
	return w.Ctx.GetReqHeaders()
}

// WriteHeader sets the HTTP status code on the wrapped Fiber context
func (w wrapCtx) WriteHeader(statusCode int) {
	w.Ctx.Status(statusCode)
}
