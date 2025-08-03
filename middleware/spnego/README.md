# SPNEGO Kerberos Authentication Middleware for Fiber

[中文版本](README.zh-CN.md)

This middleware provides SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) authentication for Fiber applications, enabling Kerberos authentication for HTTP requests.

## Features

- Kerberos authentication via SPNEGO mechanism
- Flexible keytab lookup system
- Support for dynamic keytab retrieval from various sources
- Integration with Fiber context for authenticated identity storage
- Configurable logging

## Installation

```bash
go get github.com/gofiber/fiber/v3/middleware/spnego
```

## Usage

```go
package main

import (
    flog "github.com/gofiber/fiber/v3/log"
    "fmt"

    "github.com/jcmturner/gokrb5/v8/keytab"
    "github.com/gofiber/fiber/v3"
    "github.com/gofiber/fiber/v3/middleware/spnego"
)

func main() {
    app := fiber.New()

    // Create a configuration with a keytab lookup function
    cfg := &spnego.Config{
        // Use a function to look up keytab from files
        KeytabLookup: func() (*keytab.Keytab, error) {
            // Implement your keytab lookup logic here
            // This could be from files, database, or other sources
            return spnego.NewKeytabFileLookupFunc("/path/to/keytab/file.keytab")
        },
        // Optional: Set a custom logger
        Log: flog.Default(),
    }

    // Create the middleware
    authMiddleware, err := spnego.NewSpnegoKrb5AuthenticateMiddleware(cfg)
    if err != nil {
        flog.Fatalf("Failed to create middleware: %v", err)
    }

    // Apply the middleware to protected routes
    app.Use("/protected", authMiddleware)

    // Access authenticated identity
    app.Get("/protected/resource", func(c fiber.Ctx) error {
        identity, ok := spnego.GetAuthenticatedIdentityFromContext(c)
        if !ok {
            return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
        }
        return c.SendString(fmt.Sprintf("Hello, %s!", identity.UserName()))
    })

    app.Listen(":3000")
}
```

## Dynamic Keytab Lookup

The middleware is designed with extensibility in mind, allowing keytab retrieval from various sources beyond static files:

```go
// Example: Retrieve keytab from a database
func dbKeytabLookup() (*keytab.Keytab, error) {
    // Your database lookup logic here
    // ...
    return keytabFromDatabase, nil
}

// Example: Retrieve keytab from a remote service
func remoteKeytabLookup() (*keytab.Keytab, error) {
    // Your remote service call logic here
    // ...
    return keytabFromRemote, nil
}
```

## API Reference

### `NewSpnegoKrb5AuthenticateMiddleware(cfg *Config) (fiber.Handler, error)`

Creates a new SPNEGO authentication middleware.

### `GetAuthenticatedIdentityFromContext(ctx fiber.Ctx) (goidentity.Identity, bool)`

Retrieves the authenticated identity from the Fiber context.

### `NewKeytabFileLookupFunc(keytabFiles ...string) (KeytabLookupFunc, error)`

Creates a new KeytabLookupFunc that loads keytab files.

## Configuration

The `Config` struct supports the following fields:

- `KeytabLookup`: A function that retrieves the keytab (required)
- `Log`: The logger used for middleware logging (optional, defaults to Fiber's default logger)

## Requirements

- Go 1.21 or higher
- Fiber v3
- Kerberos infrastructure

## Notes

- Ensure your Kerberos infrastructure is properly configured
- The middleware handles the SPNEGO negotiation process
- Authenticated identities are stored in the Fiber context using `contextKeyOfIdentity`
