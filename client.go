package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	client          *client.Client
	options         *OptionsV2
	toolsCache      *toolsCache
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
		var options []transport.ClientOption
		if len(v.Headers) > 0 {
			options = append(options, client.WithHeaders(v.Headers))
		}

		// Add header function to forward Authorization from context
		options = append(options, transport.WithHeaderFunc(
			func(ctx context.Context) map[string]string {
				headers := make(map[string]string)
				if authHeader, ok := authHeaderFromContext(ctx); ok {
					headers["Authorization"] = authHeader
				}
				return headers
			},
		))

		mcpClient, err := client.NewSSEMCPClient(v.URL, options...)
		if err != nil {
			return nil, err
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			needLazyLoad:    true, // Enable lazy loading for HTTP-based servers
			client:          mcpClient,
			options:         conf.Options,
			toolsCache:      newToolsCache(),
		}, nil
	case *StreamableMCPClientConfig:
		var options []transport.StreamableHTTPCOption
		if len(v.Headers) > 0 {
			options = append(options, transport.WithHTTPHeaders(v.Headers))
		}
		if v.Timeout > 0 {
			options = append(options, transport.WithHTTPTimeout(v.Timeout))
		}

		// Add header function to forward Authorization from context
		options = append(options, transport.WithHTTPHeaderFunc(
			func(ctx context.Context) map[string]string {
				headers := make(map[string]string)
				if authHeader, ok := authHeaderFromContext(ctx); ok {
					headers["Authorization"] = authHeader
				}
				return headers
			},
		))

		mcpClient, err := client.NewStreamableHttpClient(v.URL, options...)
		if err != nil {
			return nil, err
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			needLazyLoad:    true, // Enable lazy loading for HTTP-based servers
			client:          mcpClient,
			options:         conf.Options,
			toolsCache:      newToolsCache(),
		}, nil
	}
	return nil, errors.New("invalid client type")
}

func (c *Client) addToMCPServer(ctx context.Context, clientInfo mcp.Implementation, mcpServer *server.MCPServer) error {
	if c.needManualStart {
		err := c.client.Start(ctx)
		if err != nil {
			return err
		}
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
		return err
	}
	log.Printf("<%s> Successfully initialized MCP client", c.name)

	// Skip tool loading for lazy-loaded servers (OAuth-protected servers)
	// Tools will be loaded on-demand when authenticated requests come in
	if !c.needLazyLoad {
		err = c.addToolsToServer(ctx, mcpServer)
		if err != nil {
			return err
		}
	} else {
		log.Printf("<%s> Lazy loading enabled - tools will be loaded on first authenticated request", c.name)
	}

	_ = c.addPromptsToServer(ctx, mcpServer)
	_ = c.addResourcesToServer(ctx, mcpServer)
	_ = c.addResourceTemplatesToServer(ctx, mcpServer)

	if c.needPing {
		go c.startPingTask(ctx)
	}
	return nil
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

// toolsCache caches tools fetched with different auth tokens
type toolsCache struct {
	mu    sync.RWMutex
	cache map[string][]server.ServerTool // authToken -> tools
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

// loadToolsForAuth fetches tools with the given auth context and caches them
func (c *Client) loadToolsForAuth(ctx context.Context) ([]server.ServerTool, error) {
	authToken, hasAuth := authHeaderFromContext(ctx)
	if !hasAuth {
		authToken = "" // Use empty string for unauthenticated requests
	}

	// Check cache first
	if tools, ok := c.toolsCache.get(authToken); ok {
		log.Printf("<%s> Using cached tools (%d tools)", c.name, len(tools))
		return tools, nil
	}

	// Fetch tools
	log.Printf("<%s> Fetching tools with auth context", c.name)
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
	for {
		tools, err := c.client.ListTools(ctx, toolsRequest)
		if err != nil {
			return nil, err
		}
		if len(tools.Tools) == 0 {
			break
		}
		log.Printf("<%s> Successfully listed %d tools", c.name, len(tools.Tools))
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

	// Cache the tools
	c.toolsCache.set(authToken, serverTools)
	log.Printf("<%s> Cached %d tools for auth token", c.name, len(serverTools))

	return serverTools, nil
}

type Server struct {
	tokens    []string
	mcpServer *server.MCPServer
	handler   http.Handler
	client    *Client // Reference to client for lazy loading
}

func newMCPServer(name string, serverConfig *MCPProxyConfigV2, clientConfig *MCPClientConfigV2, client *Client) (*Server, error) {
	serverOpts := []server.ServerOption{
		server.WithResourceCapabilities(true, true),
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

	// Add lazy loading hooks for OAuth-protected servers
	if client.needLazyLoad {
		// Shared function to load and register tools
		loadAndRegisterTools := func(ctx context.Context) error {
			tools, err := client.loadToolsForAuth(ctx)
			if err != nil {
				return err
			}

			// Register tools globally so they can be called
			// This is safe to call multiple times - AddTool will overwrite existing tools
			for _, serverTool := range tools {
				mcpServer.AddTool(serverTool.Tool, serverTool.Handler)
			}

			return nil
		}

		// Hook to populate tools list dynamically based on auth context
		onAfterListTools := func(ctx context.Context, id any, message *mcp.ListToolsRequest, result *mcp.ListToolsResult) {
			// Load and register tools for the current auth context
			if err := loadAndRegisterTools(ctx); err != nil {
				log.Printf("<%s> Failed to load tools: %v", name, err)
				return
			}
		}

		// Hook to ensure tools are loaded before any tool call
		onBeforeCallTool := func(ctx context.Context, id any, message *mcp.CallToolRequest) {
			// Ensure tools are loaded and registered for this auth context
			if err := loadAndRegisterTools(ctx); err != nil {
				log.Printf("<%s> Failed to load tools before call: %v", name, err)
			}
		}

		// Apply hooks using the server's internal hooks
		// We need to recreate the server with hooks
		hooks := &server.Hooks{
			OnAfterListTools:   []server.OnAfterListToolsFunc{onAfterListTools},
			OnBeforeCallTool:   []server.OnBeforeCallToolFunc{onBeforeCallTool},
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
