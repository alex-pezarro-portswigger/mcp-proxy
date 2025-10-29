package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Client struct {
	name            string
	needPing        bool
	needManualStart bool
	needLazyLoad    bool
	isInitialized   bool
	isStarted       bool
	initMu          sync.Mutex
	serverURL       string
	client          *client.Client
	options         *OptionsV2
	toolsCache      *toolsCache

	deferredSSEConfig        *SSEMCPClientConfig
	deferredStreamableConfig *StreamableMCPClientConfig
}

// loggingRoundTripper wraps an http.RoundTripper to log requests and responses
type loggingRoundTripper struct {
	transport  http.RoundTripper
	serverName string
	logEnabled bool
}

type responseHeadersKey struct{}

func (lrt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if lrt.logEnabled {
		log.Printf("<%s> ≥ %s %s %s", lrt.serverName, req.Method, req.URL.RequestURI(), req.Proto)
		log.Printf("<%s> ≥ Host: %s", lrt.serverName, req.URL.Host)
		for name, values := range req.Header {
			for _, value := range values {
				log.Printf("<%s> ≥ %s: %s", lrt.serverName, name, value)
			}
		}
		log.Printf("<%s> ≥", lrt.serverName)
	}

	resp, err := lrt.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if lrt.logEnabled {
		statusText := http.StatusText(resp.StatusCode)
		if statusText == "" {
			statusText = resp.Status
		} else {
			statusText = fmt.Sprintf("%d %s", resp.StatusCode, statusText)
		}
		log.Printf("<%s> < %s %s", lrt.serverName, resp.Proto, statusText)
		for name, values := range resp.Header {
			for _, value := range values {
				log.Printf("<%s> < %s: %s", lrt.serverName, name, value)
			}
		}
		log.Printf("<%s> <", lrt.serverName)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		headersCopy := make(http.Header)
		for k, v := range resp.Header {
			headersCopy[k] = v
		}
		storeLast401Headers(lrt.serverName, headersCopy)
	}

	return resp, nil
}

// last401HeadersStore caches 401 response headers for propagation to clients
var last401HeadersStore sync.Map

func storeLast401Headers(clientName string, headers http.Header) {
	last401HeadersStore.Store(clientName, headers)
}

func getLast401Headers(clientName string) (http.Header, bool) {
	if headers, ok := last401HeadersStore.Load(clientName); ok {
		last401HeadersStore.Delete(clientName)
		return headers.(http.Header), true
	}
	return nil, false
}

// newLoggingHTTPClient creates an HTTP client with logging capability
func newLoggingHTTPClient(serverName string, logEnabled bool) *http.Client {
	return &http.Client{
		Transport: &loggingRoundTripper{
			transport:  http.DefaultTransport,
			serverName: serverName,
			logEnabled: logEnabled,
		},
		Timeout: 30 * time.Second,
	}
}

func configureSSEOptions(name string, config *SSEMCPClientConfig, logEnabled bool) []transport.ClientOption {
	var options []transport.ClientOption

	options = append(options, transport.WithHTTPClient(newLoggingHTTPClient(name, logEnabled)))

	if len(config.Headers) > 0 {
		options = append(options, client.WithHeaders(config.Headers))
	}

	options = append(options, transport.WithHeaderFunc(
		func(ctx context.Context) map[string]string {
			headers := make(map[string]string)
			if authHeader, ok := authHeaderFromContext(ctx); ok {
				headers["Authorization"] = authHeader
			}
			return headers
		},
	))

	return options
}

func configureStreamableOptions(name string, config *StreamableMCPClientConfig, logEnabled bool) []transport.StreamableHTTPCOption {
	var options []transport.StreamableHTTPCOption

	options = append(options, transport.WithHTTPBasicClient(newLoggingHTTPClient(name, logEnabled)))

	if len(config.Headers) > 0 {
		options = append(options, transport.WithHTTPHeaders(config.Headers))
	}
	if config.Timeout > 0 {
		options = append(options, transport.WithHTTPTimeout(config.Timeout))
	}

	options = append(options, transport.WithHTTPHeaderFunc(
		func(ctx context.Context) map[string]string {
			headers := make(map[string]string)
			if authHeader, ok := authHeaderFromContext(ctx); ok {
				headers["Authorization"] = authHeader
			}
			return headers
		},
	))

	return options
}

func newMCPClient(name string, conf *MCPClientConfigV2) (*Client, error) {
	clientInfo, pErr := parseMCPClientConfigV2(conf)
	if pErr != nil {
		return nil, pErr
	}
	switch v := clientInfo.(type) {
	case *StdioMCPClientConfig:
		envs := make([]string, 0, len(v.Env))
		for kk, vv := range v.Env {
			envs = append(envs, fmt.Sprintf("%s=%s", kk, vv))
		}
		mcpClient, err := client.NewStdioMCPClient(v.Command, envs, v.Args...)
		if err != nil {
			return nil, err
		}

		return &Client{
			name:    name,
			client:  mcpClient,
			options: conf.Options,
		}, nil
	case *SSEMCPClientConfig:
		ctx := context.Background()
		requiresOAuth := checkOAuthSupport(ctx, v.URL, name)

		if requiresOAuth {
			log.Printf("<%s> OAuth detected - deferring client creation until authenticated request", name)
			return &Client{
				name:              name,
				needPing:          true,
				needManualStart:   true,
				needLazyLoad:      true,
				serverURL:         v.URL,
				client:            nil,
				options:           conf.Options,
				toolsCache:        newToolsCache(),
				deferredSSEConfig: v,
			}, nil
		}

		logEnabled := conf.Options.LogEnabled.OrElse(false)
		options := configureSSEOptions(name, v, logEnabled)

		mcpClient, err := client.NewSSEMCPClient(v.URL, options...)
		if err != nil {
			return nil, err
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			needLazyLoad:    false,
			serverURL:       v.URL,
			client:          mcpClient,
			options:         conf.Options,
			toolsCache:      newToolsCache(),
		}, nil
	case *StreamableMCPClientConfig:
		ctx := context.Background()
		requiresOAuth := checkOAuthSupport(ctx, v.URL, name)

		if requiresOAuth {
			log.Printf("<%s> OAuth detected - deferring client creation until authenticated request", name)
			return &Client{
				name:                     name,
				needPing:                 true,
				needManualStart:          true,
				needLazyLoad:             true,
				serverURL:                v.URL,
				client:                   nil,
				options:                  conf.Options,
				toolsCache:               newToolsCache(),
				deferredStreamableConfig: v,
			}, nil
		}

		logEnabled := conf.Options.LogEnabled.OrElse(false)
		options := configureStreamableOptions(name, v, logEnabled)

		mcpClient, err := client.NewStreamableHttpClient(v.URL, options...)
		if err != nil {
			return nil, err
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			needLazyLoad:    false,
			serverURL:       v.URL,
			client:          mcpClient,
			options:         conf.Options,
			toolsCache:      newToolsCache(),
		}, nil
	}
	return nil, errors.New("invalid client type")
}

func (c *Client) addToMCPServer(ctx context.Context, clientInfo mcp.Implementation, mcpServer *server.MCPServer) error {
	if c.needLazyLoad {
		log.Printf("<%s> Lazy loading enabled - client will be created on first authenticated request", c.name)
		return nil
	}

	if c.needManualStart && !c.isStarted {
		err := c.client.Start(ctx)
		if err != nil {
			return err
		}
		c.isStarted = true
	}
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = clientInfo
	initRequest.Params.Capabilities = mcp.ClientCapabilities{
		Experimental: make(map[string]interface{}),
		Roots:        nil,
		Sampling:     nil,
	}
	_, err := c.client.Initialize(ctx, initRequest)
	if err != nil {
		if c.is401Error(err) && checkOAuthSupport(ctx, c.serverURL, c.name) {
			log.Printf("<%s> Server requires OAuth authentication - enabling lazy loading", c.name)
			c.needLazyLoad = true
			return nil
		}
		return err
	}
	c.isInitialized = true
	log.Printf("<%s> Successfully initialized MCP client", c.name)

	err = c.addToolsToServer(ctx, mcpServer)
	if err != nil {
		if c.is401Error(err) && checkOAuthSupport(ctx, c.serverURL, c.name) {
			log.Printf("<%s> Server requires OAuth authentication for tools - enabling lazy loading", c.name)
			c.needLazyLoad = true
			return nil
		}
		return err
	}

	_ = c.addPromptsToServer(ctx, mcpServer)
	_ = c.addResourcesToServer(ctx, mcpServer)
	_ = c.addResourceTemplatesToServer(ctx, mcpServer)

	if c.needPing {
		go c.startPingTask(ctx)
	}
	return nil
}

// is401Error checks if an error is a 401 Unauthorized error
func (c *Client) is401Error(err error) bool {
	if err == nil {
		return false
	}
	// Check for common 401 error patterns
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "unauthorized")
}

func (c *Client) startPingTask(ctx context.Context) {
	interval := 30 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("<%s> Context done, stopping ping", c.name)
			return
		case <-ticker.C:
			if err := c.client.Ping(ctx); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return
				}
				failCount++
				log.Printf("<%s> MCP Ping failed: %v (count=%d)", c.name, err, failCount)
			} else if failCount > 0 {
				log.Printf("<%s> MCP Ping recovered after %d failures", c.name, failCount)
				failCount = 0
			}
		}
	}
}

func (c *Client) addToolsToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	toolsRequest := mcp.ListToolsRequest{}
	filterFunc := func(toolName string) bool {
		return true
	}

	if c.options != nil && c.options.ToolFilter != nil && len(c.options.ToolFilter.List) > 0 {
		filterSet := make(map[string]struct{})
		mode := ToolFilterMode(strings.ToLower(string(c.options.ToolFilter.Mode)))
		for _, toolName := range c.options.ToolFilter.List {
			filterSet[toolName] = struct{}{}
		}
		switch mode {
		case ToolFilterModeAllow:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if !inList {
					log.Printf("<%s> Ignoring tool %s as it is not in allow list", c.name, toolName)
				}
				return inList
			}
		case ToolFilterModeBlock:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if inList {
					log.Printf("<%s> Ignoring tool %s as it is in block list", c.name, toolName)
				}
				return !inList
			}
		default:
			log.Printf("<%s> Unknown tool filter mode: %s, skipping tool filter", c.name, mode)
		}
	}

	for {
		tools, err := c.client.ListTools(ctx, toolsRequest)
		if err != nil {
			return err
		}
		if len(tools.Tools) == 0 {
			break
		}
		log.Printf("<%s> Successfully listed %d tools", c.name, len(tools.Tools))
		for _, tool := range tools.Tools {
			if filterFunc(tool.Name) {
				log.Printf("<%s> Adding tool %s", c.name, tool.Name)
				mcpServer.AddTool(tool, c.client.CallTool)
			}
		}
		if tools.NextCursor == "" {
			break
		}
		toolsRequest.Params.Cursor = tools.NextCursor
	}

	return nil
}

func (c *Client) addPromptsToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	promptsRequest := mcp.ListPromptsRequest{}
	for {
		prompts, err := c.client.ListPrompts(ctx, promptsRequest)
		if err != nil {
			return err
		}
		if len(prompts.Prompts) == 0 {
			break
		}
		log.Printf("<%s> Successfully listed %d prompts", c.name, len(prompts.Prompts))
		for _, prompt := range prompts.Prompts {
			log.Printf("<%s> Adding prompt %s", c.name, prompt.Name)
			mcpServer.AddPrompt(prompt, c.client.GetPrompt)
		}
		if prompts.NextCursor == "" {
			break
		}
		promptsRequest.Params.Cursor = prompts.NextCursor
	}
	return nil
}

func (c *Client) addResourcesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	resourcesRequest := mcp.ListResourcesRequest{}
	for {
		resources, err := c.client.ListResources(ctx, resourcesRequest)
		if err != nil {
			return err
		}
		if len(resources.Resources) == 0 {
			break
		}
		log.Printf("<%s> Successfully listed %d resources", c.name, len(resources.Resources))
		for _, resource := range resources.Resources {
			log.Printf("<%s> Adding resource %s", c.name, resource.Name)
			mcpServer.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}
		if resources.NextCursor == "" {
			break
		}
		resourcesRequest.Params.Cursor = resources.NextCursor

	}
	return nil
}

func (c *Client) addResourceTemplatesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	resourceTemplatesRequest := mcp.ListResourceTemplatesRequest{}
	for {
		resourceTemplates, err := c.client.ListResourceTemplates(ctx, resourceTemplatesRequest)
		if err != nil {
			return err
		}
		if len(resourceTemplates.ResourceTemplates) == 0 {
			break
		}
		log.Printf("<%s> Successfully listed %d resource templates", c.name, len(resourceTemplates.ResourceTemplates))
		for _, resourceTemplate := range resourceTemplates.ResourceTemplates {
			log.Printf("<%s> Adding resource template %s", c.name, resourceTemplate.Name)
			mcpServer.AddResourceTemplate(resourceTemplate, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}
		if resourceTemplates.NextCursor == "" {
			break
		}
		resourceTemplatesRequest.Params.Cursor = resourceTemplates.NextCursor
	}
	return nil
}

func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// ensureClientCreated creates the MCP client for lazy-loaded OAuth servers
func (c *Client) ensureClientCreated(ctx context.Context) error {
	if c.client != nil {
		return nil
	}

	if c.needLazyLoad {
		if _, hasAuth := authHeaderFromContext(ctx); !hasAuth {
			return fmt.Errorf("OAuth authentication required - please provide Authorization header")
		}
	}

	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.client != nil {
		return nil
	}

	if c.deferredSSEConfig != nil {
		logEnabled := c.options.LogEnabled.OrElse(false)
		options := configureSSEOptions(c.name, c.deferredSSEConfig, logEnabled)

		mcpClient, err := client.NewSSEMCPClient(c.deferredSSEConfig.URL, options...)
		if err != nil {
			return fmt.Errorf("failed to create SSE client: %w", err)
		}
		c.client = mcpClient
	} else if c.deferredStreamableConfig != nil {
		logEnabled := c.options.LogEnabled.OrElse(false)
		options := configureStreamableOptions(c.name, c.deferredStreamableConfig, logEnabled)

		mcpClient, err := client.NewStreamableHttpClient(c.deferredStreamableConfig.URL, options...)
		if err != nil {
			return fmt.Errorf("failed to create Streamable HTTP client: %w", err)
		}
		c.client = mcpClient
	} else {
		return fmt.Errorf("no deferred client configuration found")
	}

	return nil
}

func checkOAuthSupport(ctx context.Context, serverURL string, serverName string) bool {
	if serverURL == "" {
		return false
	}

	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return false
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	metadataEndpoints := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, endpoint := range metadataEndpoints {
		checkURL := baseURL + endpoint
		req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
		if err != nil {
			continue
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(body, &metadata); err != nil {
				continue
			}

			if _, hasIssuer := metadata["issuer"]; hasIssuer {
				log.Printf("<%s> Detected OAuth support at %s", serverName, checkURL)
				return true
			}
			if _, hasAuthEndpoint := metadata["authorization_endpoint"]; hasAuthEndpoint {
				log.Printf("<%s> Detected OAuth support at %s", serverName, checkURL)
				return true
			}
		}
	}

	return false
}

type toolsCache struct {
	mu    sync.RWMutex
	cache map[string][]server.ServerTool
}

func newToolsCache() *toolsCache {
	return &toolsCache{
		cache: make(map[string][]server.ServerTool),
	}
}

func (tc *toolsCache) get(authToken string) ([]server.ServerTool, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	tools, ok := tc.cache[authToken]
	return tools, ok
}

func (tc *toolsCache) set(authToken string, tools []server.ServerTool) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cache[authToken] = tools
}

type authError struct {
	statusCode int
	message    string
	headers    http.Header
}

func (e *authError) Error() string {
	return e.message
}

func (e *authError) StatusCode() int {
	return e.statusCode
}

func (e *authError) Headers() http.Header {
	return e.headers
}

func (c *Client) loadToolsForAuth(ctx context.Context) ([]server.ServerTool, error) {
	authToken, hasAuth := authHeaderFromContext(ctx)
	if !hasAuth {
		authToken = ""
	}

	if tools, ok := c.toolsCache.get(authToken); ok {
		return tools, nil
	}

	if err := c.ensureClientCreated(ctx); err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	if !c.isInitialized {
		c.initMu.Lock()
		defer c.initMu.Unlock()

		if c.isInitialized {
			return c.loadToolsForAuth(ctx)
		}

		if c.needManualStart && !c.isStarted {
			if err := c.client.Start(ctx); err != nil {
				if c.is401Error(err) {
					headers, _ := getLast401Headers(c.name)
					return nil, &authError{statusCode: 401, message: fmt.Sprintf("Authentication required: %v", err), headers: headers}
				}
				return nil, fmt.Errorf("failed to start client: %w", err)
			}
			c.isStarted = true
		}

		initRequest := mcp.InitializeRequest{}
		initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
		initRequest.Params.ClientInfo = mcp.Implementation{
			Name:    "mcp-proxy",
			Version: "1.0.0",
		}
		initRequest.Params.Capabilities = mcp.ClientCapabilities{
			Experimental: make(map[string]interface{}),
			Roots:        nil,
			Sampling:     nil,
		}

		if _, err := c.client.Initialize(ctx, initRequest); err != nil {
			if c.is401Error(err) {
				headers, _ := getLast401Headers(c.name)
				return nil, &authError{statusCode: 401, message: fmt.Sprintf("Authentication required: %v", err), headers: headers}
			}
			return nil, fmt.Errorf("failed to initialize client: %w", err)
		}

		c.isInitialized = true
		log.Printf("<%s> Successfully initialized MCP client", c.name)
	}

	toolsRequest := mcp.ListToolsRequest{}
	filterFunc := func(toolName string) bool {
		return true
	}

	if c.options != nil && c.options.ToolFilter != nil && len(c.options.ToolFilter.List) > 0 {
		filterSet := make(map[string]struct{})
		mode := ToolFilterMode(strings.ToLower(string(c.options.ToolFilter.Mode)))
		for _, toolName := range c.options.ToolFilter.List {
			filterSet[toolName] = struct{}{}
		}
		switch mode {
		case ToolFilterModeAllow:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if !inList {
					log.Printf("<%s> Ignoring tool %s as it is not in allow list", c.name, toolName)
				}
				return inList
			}
		case ToolFilterModeBlock:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if inList {
					log.Printf("<%s> Ignoring tool %s as it is in block list", c.name, toolName)
				}
				return !inList
			}
		default:
			log.Printf("<%s> Unknown tool filter mode: %s, skipping tool filter", c.name, mode)
		}
	}

	var serverTools []server.ServerTool
	totalToolsListed := 0
	for {
		tools, err := c.client.ListTools(ctx, toolsRequest)
		if err != nil {
			if c.is401Error(err) {
				headers, _ := getLast401Headers(c.name)
				return nil, &authError{statusCode: 401, message: fmt.Sprintf("Authentication required: %v", err), headers: headers}
			}
			return nil, err
		}
		if len(tools.Tools) == 0 {
			break
		}
		totalToolsListed += len(tools.Tools)
		for _, tool := range tools.Tools {
			if filterFunc(tool.Name) {
				log.Printf("<%s> Adding tool %s", c.name, tool.Name)
				serverTools = append(serverTools, server.ServerTool{
					Tool:    tool,
					Handler: c.client.CallTool,
				})
			}
		}
		if tools.NextCursor == "" {
			break
		}
		toolsRequest.Params.Cursor = tools.NextCursor
	}

	log.Printf("<%s> Successfully listed %d tools", c.name, totalToolsListed)

	c.toolsCache.set(authToken, serverTools)

	log.Printf("<%s> Connected", c.name)

	return serverTools, nil
}

type Server struct {
	tokens    []string
	mcpServer *server.MCPServer
	handler   http.Handler
	client    *Client
}

func newMCPServer(name string, serverConfig *MCPProxyConfigV2, clientConfig *MCPClientConfigV2, client *Client) (*Server, error) {
	serverOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	}

	if clientConfig.Options.LogEnabled.OrElse(false) {
		serverOpts = append(serverOpts, server.WithLogging())
	}

	mcpServer := server.NewMCPServer(
		name,
		serverConfig.Version,
		serverOpts...,
	)

	if client.serverURL != "" {
		loadAndRegisterTools := func(ctx context.Context) error {
			if !client.needLazyLoad {
				log.Printf("<%s> Lazy loading not enabled, skipping tool load", name)
				return nil
			}

			var initCtx context.Context
			if authHeader, ok := authHeaderFromContext(ctx); ok {
				initCtx = withAuthHeader(context.Background(), authHeader)
			} else {
				initCtx = context.Background()
			}

			tools, err := client.loadToolsForAuth(initCtx)
			if err != nil {
				return fmt.Errorf("loadToolsForAuth failed: %w", err)
			}

			for _, serverTool := range tools {
				mcpServer.AddTool(serverTool.Tool, serverTool.Handler)
			}

			return nil
		}

		onBeforeListTools := func(ctx context.Context, id any, message *mcp.ListToolsRequest) {
			if err := loadAndRegisterTools(ctx); err != nil {
				log.Printf("<%s> Failed to load tools: %v", name, err)
				// Panic with authError to propagate authentication errors to client
				var authErr *authError
				if errors.As(err, &authErr) {
					panic(authErr)
				}
				return
			}
		}

		onBeforeCallTool := func(ctx context.Context, id any, message *mcp.CallToolRequest) {
			if err := loadAndRegisterTools(ctx); err != nil {
				log.Printf("<%s> Failed to load tools before call: %v", name, err)
				// Panic with authError to propagate authentication errors to client
				var authErr *authError
				if errors.As(err, &authErr) {
					panic(authErr)
				}
			}
		}

		// Apply hooks using the server's internal hooks
		// We need to recreate the server with hooks
		hooks := &server.Hooks{
			OnBeforeListTools: []server.OnBeforeListToolsFunc{onBeforeListTools},
			OnBeforeCallTool:  []server.OnBeforeCallToolFunc{onBeforeCallTool},
		}

		// Re-create server with hooks
		serverOpts = append([]server.ServerOption{}, serverOpts...)
		serverOpts = append(serverOpts, server.WithHooks(hooks))

		mcpServer = server.NewMCPServer(
			name,
			serverConfig.Version,
			serverOpts...,
		)
	}

	var handler http.Handler

	switch serverConfig.Type {
	case MCPServerTypeSSE:
		handler = server.NewSSEServer(
			mcpServer,
			server.WithStaticBasePath(name),
			server.WithBaseURL(serverConfig.BaseURL),
		)
	case MCPServerTypeStreamable:
		handler = server.NewStreamableHTTPServer(
			mcpServer,
			server.WithStateLess(true),
			server.WithHTTPContextFunc(
				func(ctx context.Context, r *http.Request) context.Context {
					authHeader := r.Header.Get("Authorization")
					if authHeader != "" {
						return withAuthHeader(ctx, authHeader)
					}
					return ctx
				},
			),
		)
	default:
		return nil, fmt.Errorf("unknown server type: %s", serverConfig.Type)
	}
	srv := &Server{
		mcpServer: mcpServer,
		handler:   handler,
		client:    client,
	}

	if clientConfig.Options != nil && len(clientConfig.Options.AuthTokens) > 0 {
		srv.tokens = clientConfig.Options.AuthTokens
	}

	return srv, nil
}
