package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

type MiddlewareFunc func(http.Handler) http.Handler

// authHeaderKey is a context key for storing Authorization headers
type authHeaderKey struct{}

// withAuthHeader adds an auth header to context
func withAuthHeader(ctx context.Context, authHeader string) context.Context {
	return context.WithValue(ctx, authHeaderKey{}, authHeader)
}

// authHeaderFromContext extracts auth header from context
func authHeaderFromContext(ctx context.Context) (string, bool) {
	auth, ok := ctx.Value(authHeaderKey{}).(string)
	return auth, ok
}

func chainMiddleware(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, mw := range middlewares {
		h = mw(h)
	}
	return h
}

func newAuthMiddleware(tokens []string) MiddlewareFunc {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) != 0 {
				token := r.Header.Get("Authorization")
				token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
				if token == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				if _, ok := tokenSet[token]; !ok {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggerMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("<%s> Request [%s] %s", prefix, r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

func recoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("<%s> Recovered from panic: %v", prefix, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func startHTTPServer(config *Config) error {
	baseURL, uErr := url.Parse(config.McpProxy.BaseURL)
	if uErr != nil {
		return uErr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorGroup errgroup.Group
	httpMux := http.NewServeMux()
	httpServer := &http.Server{
		Addr:    config.McpProxy.Addr,
		Handler: httpMux,
	}
	info := mcp.Implementation{
		Name: config.McpProxy.Name,
	}

	// Register OAuth discovery endpoints for each MCP server
	for name, clientConfig := range config.McpServers {
		if clientConfig.URL == "" {
			continue // Skip non-HTTP servers (e.g., command-based servers)
		}

		// Parse the base URL for the MCP server
		serverBaseURL, err := url.Parse(clientConfig.URL)
		if err != nil {
			log.Printf("<%s> Failed to parse server URL for discovery endpoints: %v", name, err)
			continue
		}

		// Set base URL to scheme://host (strip path)
		serverBaseURL.Path = ""
		serverBaseURL.RawQuery = ""
		serverBaseURL.Fragment = ""

		// Register discovery endpoints with server name prefix
		registerDiscoveryEndpoints(httpMux, name, serverBaseURL.String())
		log.Printf("<%s> Registered OAuth discovery endpoints", name)
	}

	for name, clientConfig := range config.McpServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			return err
		}
		server, err := newMCPServer(name, config.McpProxy, clientConfig)
		if err != nil {
			return err
		}

		// Register route immediately, regardless of initialization status
		// This allows OAuth-protected servers to receive requests with Authorization headers
		middlewares := make([]MiddlewareFunc, 0)
		middlewares = append(middlewares, recoverMiddleware(name))
		if clientConfig.Options.LogEnabled.OrElse(false) {
			middlewares = append(middlewares, loggerMiddleware(name))
		}
		if len(clientConfig.Options.AuthTokens) > 0 {
			middlewares = append(middlewares, newAuthMiddleware(clientConfig.Options.AuthTokens))
		}
		mcpRoute := path.Join(baseURL.Path, name)
		if !strings.HasPrefix(mcpRoute, "/") {
			mcpRoute = "/" + mcpRoute
		}
		if !strings.HasSuffix(mcpRoute, "/") {
			mcpRoute += "/"
		}
		log.Printf("<%s> Handling requests at %s", name, mcpRoute)
		httpMux.Handle(mcpRoute, chainMiddleware(server.handler, middlewares...))

		// Initialize in background
		errorGroup.Go(func() error {
			log.Printf("<%s> Connecting", name)
			addErr := mcpClient.addToMCPServer(ctx, info, server.mcpServer)
			if addErr != nil {
				log.Printf("<%s> Failed to add client to server: %v", name, addErr)
				if clientConfig.Options.PanicIfInvalid.OrElse(false) {
					return addErr
				}
				return nil
			}
			log.Printf("<%s> Connected", name)
			return nil
		})

		httpServer.RegisterOnShutdown(func() {
			log.Printf("<%s> Shutting down", name)
			_ = mcpClient.Close()
		})
	}

	go func() {
		err := errorGroup.Wait()
		if err != nil {
			log.Fatalf("Failed to add clients: %v", err)
		}
		log.Printf("All clients initialized")
	}()

	go func() {
		log.Printf("Starting %s server", config.McpProxy.Type)
		log.Printf("%s server listening on %s", config.McpProxy.Type, config.McpProxy.Addr)
		hErr := httpServer.ListenAndServe()
		if hErr != nil && !errors.Is(hErr, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", hErr)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	err := httpServer.Shutdown(shutdownCtx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// registerDiscoveryEndpoints registers OAuth/OIDC discovery endpoints for a server
func registerDiscoveryEndpoints(mux *http.ServeMux, serverName, backendURL string) {
	discoveryPaths := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource",
	}

	// Register discovery endpoints with server name suffix (e.g., /.well-known/oauth-authorization-server/atlassian)
	for _, discoveryPath := range discoveryPaths {
		// Register with server name suffix
		pathWithSuffix := discoveryPath + "/" + serverName
		mux.HandleFunc(pathWithSuffix, createProxyHandler(backendURL, discoveryPath, serverName))

		// Also register with /mcp suffix for clients that append it
		pathWithMCP := discoveryPath + "/" + serverName + "/mcp"
		mux.HandleFunc(pathWithMCP, createProxyHandler(backendURL, discoveryPath, serverName))
	}

	// Register server-prefixed discovery endpoints (e.g., /atlassian/mcp/.well-known/openid-configuration)
	for _, discoveryPath := range discoveryPaths {
		path := "/" + serverName + discoveryPath
		mux.HandleFunc(path, createProxyHandler(backendURL, discoveryPath, serverName))
	}

	// Register dynamic client registration endpoint
	registerPath := "/" + serverName + "/register"
	mux.HandleFunc(registerPath, createProxyHandler(backendURL, "/register", serverName))
}

// createProxyHandler creates an HTTP handler that proxies requests to a backend server
func createProxyHandler(backendURL, targetPath, serverName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build target URL
		target := backendURL + targetPath
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		// Create proxy request
		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil {
			log.Printf("<%s> Failed to create proxy request: %v", serverName, err)
			http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
			return
		}

		// Copy headers from original request
		for name, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(name, value)
			}
		}

		// Set/override Host header to backend
		backendURLParsed, _ := url.Parse(backendURL)
		proxyReq.Host = backendURLParsed.Host

		// Execute proxy request
		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("<%s> Proxy request failed: %v", serverName, err)
			http.Error(w, "Proxy request failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}

		// Write response status and body
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("<%s> Failed to write proxy response: %v", serverName, err)
		}
	}
}
