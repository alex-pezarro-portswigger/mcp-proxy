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

type authHeaderKey struct{}

func withAuthHeader(ctx context.Context, authHeader string) context.Context {
	return context.WithValue(ctx, authHeaderKey{}, authHeader)
}

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

func newOAuthRequiredMiddleware(serverName string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.Printf("<%s> Request rejected - OAuth authentication required", serverName)
				http.Error(w, "Unauthorized - OAuth authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggerMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("<%s> > %s %s %s", prefix, r.Method, r.URL.RequestURI(), r.Proto)
			log.Printf("<%s> > Host: %s", prefix, r.Host)
			for name, values := range r.Header {
				for _, value := range values {
					log.Printf("<%s> > %s: %s", prefix, name, value)
				}
			}
			log.Printf("<%s> >", prefix)

			loggingWriter := &loggingResponseWriter{
				ResponseWriter: w,
				prefix:         prefix,
			}

			next.ServeHTTP(loggingWriter, r)

			loggingWriter.logResponse()
		})
	}
}

// loggingResponseWriter wraps http.ResponseWriter to capture response details
type loggingResponseWriter struct {
	http.ResponseWriter
	prefix        string
	statusCode    int
	headerLogged  bool
	responseLogged bool
}

func (lw *loggingResponseWriter) WriteHeader(statusCode int) {
	lw.statusCode = statusCode
	lw.logResponseHeader()
	lw.ResponseWriter.WriteHeader(statusCode)
}

func (lw *loggingResponseWriter) Write(data []byte) (int, error) {
	if lw.statusCode == 0 {
		lw.statusCode = http.StatusOK
		lw.logResponseHeader()
	}
	return lw.ResponseWriter.Write(data)
}

func (lw *loggingResponseWriter) logResponseHeader() {
	if lw.headerLogged {
		return
	}
	lw.headerLogged = true

	statusText := http.StatusText(lw.statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}
	log.Printf("<%s> ≤ HTTP/1.1 %d %s", lw.prefix, lw.statusCode, statusText)
	for name, values := range lw.Header() {
		for _, value := range values {
			log.Printf("<%s> ≤ %s: %s", lw.prefix, name, value)
		}
	}
}

func (lw *loggingResponseWriter) logResponse() {
	if lw.responseLogged {
		return
	}
	lw.responseLogged = true

	if !lw.headerLogged {
		lw.logResponseHeader()
	}
	log.Printf("<%s> ≤", lw.prefix)
}

func recoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					if authErr, ok := err.(interface {
						Error() string
						StatusCode() int
						Headers() http.Header
					}); ok {
						statusCode := authErr.StatusCode()
						if statusCode == 401 {
							log.Printf("<%s> Authentication error: %v", prefix, err)

							headers := authErr.Headers()
							if headers != nil {
								for name, values := range headers {
									for _, value := range values {
										w.Header().Add(name, value)
									}
								}
							}

							w.WriteHeader(http.StatusUnauthorized)
							w.Write([]byte("Unauthorized\n"))
							return
						}
					}
					log.Printf("<%s> Recovered from panic: %v", prefix, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func newAuthErrorDetectionMiddleware(serverName string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapper := &responseWrapper{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				serverName:     serverName,
			}

			next.ServeHTTP(wrapper, r)

			wrapper.finalizeResponse()
		})
	}
}

// responseWrapper wraps http.ResponseWriter to intercept and potentially modify responses
type responseWrapper struct {
	http.ResponseWriter
	statusCode     int
	headerWritten  bool
	serverName     string
	bodyBuf        []byte
	isStreaming    bool
	checkedStreaming bool
}

func (rw *responseWrapper) WriteHeader(statusCode int) {
	if rw.headerWritten {
		return
	}
	rw.statusCode = statusCode
	rw.checkIfStreaming()

	if rw.isStreaming {
		rw.ResponseWriter.WriteHeader(rw.statusCode)
		rw.headerWritten = true
	}
}

func (rw *responseWrapper) checkIfStreaming() {
	if rw.checkedStreaming {
		return
	}
	rw.checkedStreaming = true

	contentType := rw.Header().Get("Content-Type")
	rw.isStreaming = strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "application/x-ndjson") ||
		strings.Contains(contentType, "multipart/")
}

func (rw *responseWrapper) Write(data []byte) (int, error) {
	rw.checkIfStreaming()

	if rw.isStreaming {
		if !rw.headerWritten {
			if rw.statusCode == 0 {
				rw.statusCode = http.StatusOK
			}
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			rw.headerWritten = true
		}
		return rw.ResponseWriter.Write(data)
	}

	rw.bodyBuf = append(rw.bodyBuf, data...)
	return len(data), nil
}

func (rw *responseWrapper) finalizeResponse() {
	if rw.headerWritten {
		return
	}

	contentType := rw.Header().Get("Content-Type")
	if strings.Contains(contentType, "application/json") && len(rw.bodyBuf) > 0 {
		bodyStr := string(rw.bodyBuf)

		if strings.Contains(bodyStr, `"error"`) &&
			(strings.Contains(bodyStr, "401") ||
				strings.Contains(bodyStr, "Unauthorized") ||
				strings.Contains(bodyStr, "unauthorized")) {

			log.Printf("<%s> Detected 401 error in response, setting HTTP status to 401", rw.serverName)
			rw.statusCode = http.StatusUnauthorized
		}
	}

	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	rw.ResponseWriter.WriteHeader(rw.statusCode)
	rw.headerWritten = true

	if len(rw.bodyBuf) > 0 {
		rw.ResponseWriter.Write(rw.bodyBuf)
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

		serverBaseURL.Path = ""
		serverBaseURL.RawQuery = ""
		serverBaseURL.Fragment = ""

		registerDiscoveryEndpoints(httpMux, name, serverBaseURL.String())
		log.Printf("<%s> Registered OAuth discovery endpoints", name)
	}

	for name, clientConfig := range config.McpServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			return err
		}
		server, err := newMCPServer(name, config.McpProxy, clientConfig, mcpClient)
		if err != nil {
			return err
		}

		middlewares := make([]MiddlewareFunc, 0)
		middlewares = append(middlewares, recoverMiddleware(name))
		if clientConfig.Options.LogEnabled.OrElse(false) {
			middlewares = append(middlewares, loggerMiddleware(name))
		}
		if mcpClient.needLazyLoad {
			middlewares = append(middlewares, newOAuthRequiredMiddleware(name))
		} else if len(clientConfig.Options.AuthTokens) > 0 {
			middlewares = append(middlewares, newAuthMiddleware(clientConfig.Options.AuthTokens))
		}
		middlewares = append(middlewares, newAuthErrorDetectionMiddleware(name))
		mcpRoute := path.Join(baseURL.Path, name)
		if !strings.HasPrefix(mcpRoute, "/") {
			mcpRoute = "/" + mcpRoute
		}
		if !strings.HasSuffix(mcpRoute, "/") {
			mcpRoute += "/"
		}
		log.Printf("<%s> Handling requests at %s", name, mcpRoute)
		httpMux.Handle(mcpRoute, chainMiddleware(server.handler, middlewares...))

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

	registerPath := "/" + serverName + "/register"
	mux.HandleFunc(registerPath, createProxyHandler(backendURL, "/register", serverName))
}

func createProxyHandler(backendURL, targetPath, serverName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := backendURL + targetPath
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil {
			log.Printf("<%s> Failed to create proxy request: %v", serverName, err)
			http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
			return
		}

		for name, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(name, value)
			}
		}

		backendURLParsed, _ := url.Parse(backendURL)
		proxyReq.Host = backendURLParsed.Host

		log.Printf("<%s> ≥ %s %s %s", serverName, proxyReq.Method, proxyReq.URL.RequestURI(), proxyReq.Proto)
		log.Printf("<%s> ≥ Host: %s", serverName, proxyReq.Host)
		for name, values := range proxyReq.Header {
			for _, value := range values {
				log.Printf("<%s> ≥ %s: %s", serverName, name, value)
			}
		}
		log.Printf("<%s> ≥", serverName)

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

		log.Printf("<%s> < HTTP/1.1 %d %s", serverName, resp.StatusCode, resp.Status)
		for name, values := range resp.Header {
			for _, value := range values {
				log.Printf("<%s> < %s: %s", serverName, name, value)
			}
		}
		log.Printf("<%s> <", serverName)

		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}

		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("<%s> Failed to write proxy response: %v", serverName, err)
		}
	}
}
