// PicoClaw - Ultra-lightweight personal AI agent
// Inspired by and based on nanobot: https://github.com/HKUDS/nanobot
// License: MIT
//
// Copyright (c) 2026 PicoClaw contributors

package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sipeed/picoclaw/pkg/auth"
	"github.com/sipeed/picoclaw/pkg/config"
)

type HTTPProvider struct {
	apiKey     string
	apiBase    string
	httpClient *http.Client
}

func NewHTTPProvider(apiKey, apiBase, proxy string) *HTTPProvider {
	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client.Transport = transport

	return &HTTPProvider{
		apiKey:     apiKey,
		apiBase:    strings.TrimRight(apiBase, "/"),
		httpClient: client,
	}
}

func (p *HTTPProvider) Chat(ctx context.Context, messages []Message, tools []ToolDefinition, model string, options map[string]interface{}) (*LLMResponse, error) {
	if p.apiBase == "" {
		return nil, fmt.Errorf("API base not configured")
	}

	// Strip provider prefix from model name (e.g., moonshot/kimi-k2.5 -> kimi-k2.5, groq/openai/gpt-oss-120b -> openai/gpt-oss-120b, ollama/qwen2.5:14b -> qwen2.5:14b)
	if idx := strings.Index(model, "/"); idx != -1 {
		prefix := model[:idx]
		if prefix == "moonshot" || prefix == "nvidia" || prefix == "groq" || prefix == "ollama" || prefix == "newapi" {
			model = model[idx+1:]
		}
	}

	// Gateway Logic for Grok: Rename tools to avoid "unsupported name" error
	// Grok is strict about tool names (e.g. read_file is rejected).
	// We map them to safe names here and map back in the response.
	// Gateway Logic for Grok: Rename tools to avoid "unsupported name" error
	isGrok := IsGrokModel(model)

	effectiveTools := tools
	if isGrok && len(tools) > 0 {
		effectiveTools = FilterAndRenameGrokTools(tools)
	}

	effectiveMessages := messages
	if isGrok {
		effectiveMessages = RenameGrokToolCalls(messages)
	}

	var payloadMessages []map[string]interface{}
	for _, m := range effectiveMessages {
		msgMap := map[string]interface{}{
			"role": m.Role,
		}

		if len(m.Media) > 0 {
			contentArr := []map[string]interface{}{}
			if m.Content != "" {
				contentArr = append(contentArr, map[string]interface{}{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, mediaURL := range m.Media {
				if strings.HasPrefix(mediaURL, "http") {
					encodedURL, err := fetchAndEncodeImage(ctx, p.httpClient, mediaURL)
					if err == nil {
						mediaURL = encodedURL
					}
				}
				contentArr = append(contentArr, map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]interface{}{
						"url": mediaURL,
					},
				})
			}
			msgMap["content"] = contentArr
		} else {
			msgMap["content"] = m.Content
		}

		if len(m.ToolCalls) > 0 {
			msgMap["tool_calls"] = m.ToolCalls
		}
		if m.ToolCallID != "" {
			msgMap["tool_call_id"] = m.ToolCallID
		}
		if m.ReasoningContent != "" {
			msgMap["reasoning_content"] = m.ReasoningContent
		}

		payloadMessages = append(payloadMessages, msgMap)
	}

	requestBody := map[string]interface{}{
		"model":    model,
		"messages": payloadMessages,
	}

	if len(effectiveTools) > 0 {
		requestBody["tools"] = effectiveTools
		requestBody["tool_choice"] = "auto"
	}

	if maxTokens, ok := options["max_tokens"].(int); ok {
		lowerModel := strings.ToLower(model)
		if strings.Contains(lowerModel, "glm") || strings.Contains(lowerModel, "o1") {
			requestBody["max_completion_tokens"] = maxTokens
		} else {
			requestBody["max_tokens"] = maxTokens
		}
	}

	if temperature, ok := options["temperature"].(float64); ok {
		lowerModel := strings.ToLower(model)
		// Kimi k2 models only support temperature=1
		if strings.Contains(lowerModel, "kimi") && strings.Contains(lowerModel, "k2") {
			requestBody["temperature"] = 1.0
		} else {
			requestBody["temperature"] = temperature
		}
	}

	requestBody["stream"] = true

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.apiBase+"/chat/completions", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed:\n  Status: %d\n  Body:   %s", resp.StatusCode, string(body))
	}

	response, err := p.parseResponse(body)
	if err != nil {
		return nil, err
	}

	// Gateway Logic: Map back tool names for Grok
	// Gateway Logic: Map back tool names for Grok
	if isGrok && response != nil && len(response.ToolCalls) > 0 {
		for i, tc := range response.ToolCalls {
			response.ToolCalls[i].Name = GetOriginalToolName(tc.Name)
		}
	}

	return response, nil
}

func fetchAndEncodeImage(ctx context.Context, client *http.Client, urlStr string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "image/jpeg"
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

func (p *HTTPProvider) parseResponse(body []byte) (*LLMResponse, error) {
	type choice struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content,omitempty"`
			Thinking         string `json:"thinking,omitempty"`
			ToolCalls        []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function *struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}

	var fullResp struct {
		Choices []choice   `json:"choices"`
		Usage   *UsageInfo `json:"usage"`
	}

	// Try standard unmarshal first
	if err := json.Unmarshal(body, &fullResp); err == nil && (len(fullResp.Choices) > 0 || fullResp.Usage != nil) {
		// Valid single JSON response
	} else {
		// Fallback: Handle multi-line stream/SSE format
		lines := bytes.Split(body, []byte("\n"))
		contentBuilder := strings.Builder{}
		reasoningBuilder := strings.Builder{}

		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			if bytes.HasPrefix(line, []byte("data: ")) {
				line = bytes.TrimPrefix(line, []byte("data: "))
			}

			if string(line) == "[DONE]" {
				continue
			}

			// Define a struct for stream chunks (delta)
			var streamChunk struct {
				Choices []struct {
					Delta struct {
						Content          string `json:"content"`
						ReasoningContent string `json:"reasoning_content"`
						Thinking         string `json:"thinking"`
						ToolCalls        []struct {
							Index    int    `json:"index"`
							ID       string `json:"id"`
							Type     string `json:"type"`
							Function *struct {
								Name      string `json:"name"`
								Arguments string `json:"arguments"`
							} `json:"function"`
						} `json:"tool_calls"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
				Usage *UsageInfo `json:"usage"`
			}

			if err := json.Unmarshal(line, &streamChunk); err == nil {
				if len(streamChunk.Choices) > 0 {
					contentBuilder.WriteString(streamChunk.Choices[0].Delta.Content)
					reasoningBuilder.WriteString(streamChunk.Choices[0].Delta.ReasoningContent)
					reasoningBuilder.WriteString(streamChunk.Choices[0].Delta.Thinking)
					if streamChunk.Choices[0].FinishReason != "" {
						var c choice
						c.FinishReason = streamChunk.Choices[0].FinishReason
						fullResp.Choices = append(fullResp.Choices, c)
					}

					// Pre-allocate or access choices[0] message tool calls
					if len(fullResp.Choices) == 0 {
						fullResp.Choices = make([]choice, 1)
					}

					for _, tcDelta := range streamChunk.Choices[0].Delta.ToolCalls {
						// Ensure the tool_calls slice is large enough
						for len(fullResp.Choices[0].Message.ToolCalls) <= tcDelta.Index {
							fullResp.Choices[0].Message.ToolCalls = append(fullResp.Choices[0].Message.ToolCalls, struct {
								ID       string "json:\"id\""
								Type     string "json:\"type\""
								Function *struct {
									Name      string "json:\"name\""
									Arguments string "json:\"arguments\""
								} "json:\"function\""
							}{})
						}

						if tcDelta.ID != "" {
							fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].ID = tcDelta.ID
						}
						if tcDelta.Type != "" {
							fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].Type = tcDelta.Type
						}

						if tcDelta.Function != nil {
							if fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].Function == nil {
								fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].Function = &struct {
									Name      string "json:\"name\""
									Arguments string "json:\"arguments\""
								}{}
							}
							if tcDelta.Function.Name != "" {
								fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].Function.Name += tcDelta.Function.Name
							}
							if tcDelta.Function.Arguments != "" {
								fullResp.Choices[0].Message.ToolCalls[tcDelta.Index].Function.Arguments += tcDelta.Function.Arguments
							}
						}
					}
				}
				if streamChunk.Usage != nil {
					fullResp.Usage = streamChunk.Usage
				}
			}
		}

		// Synthesize a full response from aggregated chunks
		if contentBuilder.Len() > 0 || reasoningBuilder.Len() > 0 {
			if len(fullResp.Choices) == 0 {
				fullResp.Choices = make([]choice, 1)
			}
			fullResp.Choices[0].Message.Content = contentBuilder.String()
			fullResp.Choices[0].Message.ReasoningContent = reasoningBuilder.String()
		} else if len(fullResp.Choices) == 0 && fullResp.Usage == nil {
			return nil, fmt.Errorf("failed to parse response as JSON or Stream: %s", string(body))
		}
	}

	if len(fullResp.Choices) == 0 {
		return &LLMResponse{
			Content:      "",
			FinishReason: "stop",
		}, nil
	}

	c := fullResp.Choices[0]

	reasoning := c.Message.ReasoningContent
	if reasoning == "" {
		reasoning = c.Message.Thinking
	}

	toolCalls := make([]ToolCall, 0, len(c.Message.ToolCalls))
	for _, tc := range c.Message.ToolCalls {
		arguments := make(map[string]interface{})
		name := ""

		// Handle OpenAI format with nested function object
		if tc.Type == "function" && tc.Function != nil {
			name = tc.Function.Name
			if tc.Function.Arguments != "" {
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &arguments); err != nil {
					arguments["raw"] = tc.Function.Arguments
				}
			}
		} else if tc.Function != nil {
			// Legacy format without type field
			name = tc.Function.Name
			if tc.Function.Arguments != "" {
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &arguments); err != nil {
					arguments["raw"] = tc.Function.Arguments
				}
			}
		}

		toolCalls = append(toolCalls, ToolCall{
			ID:        tc.ID,
			Name:      name,
			Arguments: arguments,
		})
	}

	return &LLMResponse{
		Content:          c.Message.Content,
		ReasoningContent: reasoning,
		ToolCalls:        toolCalls,
		FinishReason:     c.FinishReason,
		Usage:            fullResp.Usage,
	}, nil
}

func (p *HTTPProvider) GetDefaultModel() string {
	return ""
}

func createClaudeAuthProvider() (LLMProvider, error) {
	cred, err := auth.GetCredential("anthropic")
	if err != nil {
		return nil, fmt.Errorf("loading auth credentials: %w", err)
	}
	if cred == nil {
		return nil, fmt.Errorf("no credentials for anthropic. Run: picoclaw auth login --provider anthropic")
	}
	return NewClaudeProviderWithTokenSource(cred.AccessToken, createClaudeTokenSource()), nil
}

func createCodexAuthProvider() (LLMProvider, error) {
	cred, err := auth.GetCredential("openai")
	if err != nil {
		return nil, fmt.Errorf("loading auth credentials: %w", err)
	}
	if cred == nil {
		return nil, fmt.Errorf("no credentials for openai. Run: picoclaw auth login --provider openai")
	}
	return NewCodexProviderWithTokenSource(cred.AccessToken, cred.AccountID, createCodexTokenSource()), nil
}

func CreateProvider(cfg *config.Config) (LLMProvider, error) {
	model := cfg.Agents.Defaults.Model
	providerName := strings.ToLower(cfg.Agents.Defaults.Provider)

	var apiKey, apiBase, proxy string

	lowerModel := strings.ToLower(model)

	// First, try to use explicitly configured provider
	if providerName != "" {
		switch providerName {
		case "groq":
			if cfg.Providers.Groq.APIKey != "" {
				apiKey = cfg.Providers.Groq.APIKey
				apiBase = cfg.Providers.Groq.APIBase
				if apiBase == "" {
					apiBase = "https://api.groq.com/openai/v1"
				}
			}
		case "openai", "gpt":
			if cfg.Providers.OpenAI.APIKey != "" || cfg.Providers.OpenAI.AuthMethod != "" {
				if cfg.Providers.OpenAI.AuthMethod == "codex-cli" {
					return NewCodexProviderWithTokenSource("", "", CreateCodexCliTokenSource()), nil
				}
				if cfg.Providers.OpenAI.AuthMethod == "oauth" || cfg.Providers.OpenAI.AuthMethod == "token" {
					return createCodexAuthProvider()
				}
				apiKey = cfg.Providers.OpenAI.APIKey
				apiBase = cfg.Providers.OpenAI.APIBase
				if apiBase == "" {
					apiBase = "https://api.openai.com/v1"
				}
			}
		case "anthropic", "claude":
			if cfg.Providers.Anthropic.APIKey != "" || cfg.Providers.Anthropic.AuthMethod != "" {
				if cfg.Providers.Anthropic.AuthMethod == "oauth" || cfg.Providers.Anthropic.AuthMethod == "token" {
					return createClaudeAuthProvider()
				}
				apiKey = cfg.Providers.Anthropic.APIKey
				apiBase = cfg.Providers.Anthropic.APIBase
				if apiBase == "" {
					apiBase = "https://api.anthropic.com/v1"
				}
			}
		case "openrouter":
			if cfg.Providers.OpenRouter.APIKey != "" {
				apiKey = cfg.Providers.OpenRouter.APIKey
				if cfg.Providers.OpenRouter.APIBase != "" {
					apiBase = cfg.Providers.OpenRouter.APIBase
				} else {
					apiBase = "https://openrouter.ai/api/v1"
				}
			}
		case "zhipu", "glm":
			if cfg.Providers.Zhipu.APIKey != "" {
				apiKey = cfg.Providers.Zhipu.APIKey
				apiBase = cfg.Providers.Zhipu.APIBase
				if apiBase == "" {
					apiBase = "https://open.bigmodel.cn/api/paas/v4"
				}
			}
		case "gemini", "google":
			if cfg.Providers.Gemini.APIKey != "" {
				apiKey = cfg.Providers.Gemini.APIKey
				apiBase = cfg.Providers.Gemini.APIBase
				if apiBase == "" {
					apiBase = "https://generativelanguage.googleapis.com/v1beta"
				}
			}
		case "vllm":
			if cfg.Providers.VLLM.APIBase != "" {
				apiKey = cfg.Providers.VLLM.APIKey
				apiBase = cfg.Providers.VLLM.APIBase
			}
		case "shengsuanyun":
			if cfg.Providers.ShengSuanYun.APIKey != "" {
				apiKey = cfg.Providers.ShengSuanYun.APIKey
				apiBase = cfg.Providers.ShengSuanYun.APIBase
				if apiBase == "" {
					apiBase = "https://router.shengsuanyun.com/api/v1"
				}
			}
		case "claude-cli", "claudecode", "claude-code":
			workspace := cfg.WorkspacePath()
			if workspace == "" {
				workspace = "."
			}
			return NewClaudeCliProvider(workspace), nil
		case "codex-cli", "codex-code":
			workspace := cfg.WorkspacePath()
			if workspace == "" {
				workspace = "."
			}
			return NewCodexCliProvider(workspace), nil
		case "deepseek":
			if cfg.Providers.DeepSeek.APIKey != "" {
				apiKey = cfg.Providers.DeepSeek.APIKey
				apiBase = cfg.Providers.DeepSeek.APIBase
				if apiBase == "" {
					apiBase = "https://api.deepseek.com/v1"
				}
				if model != "deepseek-chat" && model != "deepseek-reasoner" {
					model = "deepseek-chat"
				}
			}
		case "github_copilot", "copilot":
			if cfg.Providers.GitHubCopilot.APIBase != "" {
				apiBase = cfg.Providers.GitHubCopilot.APIBase
			} else {
				apiBase = "localhost:4321"
			}
			return NewGitHubCopilotProvider(apiBase, cfg.Providers.GitHubCopilot.ConnectMode, model)

		case "newapi":
			if cfg.Providers.NewAPI.APIKey != "" {
				apiKey = cfg.Providers.NewAPI.APIKey
				apiBase = cfg.Providers.NewAPI.APIBase
				if apiBase == "" {
					apiBase = "https://newapi.sorai.me/v1"
				}
			}
		}
	}

	// Fallback: detect provider from model name
	if apiKey == "" && apiBase == "" {
		switch {
		case (strings.Contains(lowerModel, "kimi") || strings.Contains(lowerModel, "moonshot") || strings.HasPrefix(model, "moonshot/")) && cfg.Providers.Moonshot.APIKey != "":
			apiKey = cfg.Providers.Moonshot.APIKey
			apiBase = cfg.Providers.Moonshot.APIBase
			proxy = cfg.Providers.Moonshot.Proxy
			if apiBase == "" {
				apiBase = "https://api.moonshot.cn/v1"
			}

		case strings.HasPrefix(model, "openrouter/") || strings.HasPrefix(model, "anthropic/") || strings.HasPrefix(model, "openai/") || strings.HasPrefix(model, "meta-llama/") || strings.HasPrefix(model, "deepseek/") || strings.HasPrefix(model, "google/"):
			apiKey = cfg.Providers.OpenRouter.APIKey
			proxy = cfg.Providers.OpenRouter.Proxy
			if cfg.Providers.OpenRouter.APIBase != "" {
				apiBase = cfg.Providers.OpenRouter.APIBase
			} else {
				apiBase = "https://openrouter.ai/api/v1"
			}

		case (strings.Contains(lowerModel, "claude") || strings.HasPrefix(model, "anthropic/")) && (cfg.Providers.Anthropic.APIKey != "" || cfg.Providers.Anthropic.AuthMethod != ""):
			if cfg.Providers.Anthropic.AuthMethod == "oauth" || cfg.Providers.Anthropic.AuthMethod == "token" {
				return createClaudeAuthProvider()
			}
			apiKey = cfg.Providers.Anthropic.APIKey
			apiBase = cfg.Providers.Anthropic.APIBase
			proxy = cfg.Providers.Anthropic.Proxy
			if apiBase == "" {
				apiBase = "https://api.anthropic.com/v1"
			}

		case (strings.Contains(lowerModel, "gpt") || strings.HasPrefix(model, "openai/")) && (cfg.Providers.OpenAI.APIKey != "" || cfg.Providers.OpenAI.AuthMethod != ""):
			if cfg.Providers.OpenAI.AuthMethod == "oauth" || cfg.Providers.OpenAI.AuthMethod == "token" {
				return createCodexAuthProvider()
			}
			apiKey = cfg.Providers.OpenAI.APIKey
			apiBase = cfg.Providers.OpenAI.APIBase
			proxy = cfg.Providers.OpenAI.Proxy
			if apiBase == "" {
				apiBase = "https://api.openai.com/v1"
			}

		case (strings.Contains(lowerModel, "gemini") || strings.HasPrefix(model, "google/")) && cfg.Providers.Gemini.APIKey != "":
			apiKey = cfg.Providers.Gemini.APIKey
			apiBase = cfg.Providers.Gemini.APIBase
			proxy = cfg.Providers.Gemini.Proxy
			if apiBase == "" {
				apiBase = "https://generativelanguage.googleapis.com/v1beta"
			}

		case (strings.Contains(lowerModel, "glm") || strings.Contains(lowerModel, "zhipu") || strings.Contains(lowerModel, "zai")) && cfg.Providers.Zhipu.APIKey != "":
			apiKey = cfg.Providers.Zhipu.APIKey
			apiBase = cfg.Providers.Zhipu.APIBase
			proxy = cfg.Providers.Zhipu.Proxy
			if apiBase == "" {
				apiBase = "https://open.bigmodel.cn/api/paas/v4"
			}

		case (strings.Contains(lowerModel, "groq") || strings.HasPrefix(model, "groq/")) && cfg.Providers.Groq.APIKey != "":
			apiKey = cfg.Providers.Groq.APIKey
			apiBase = cfg.Providers.Groq.APIBase
			proxy = cfg.Providers.Groq.Proxy
			if apiBase == "" {
				apiBase = "https://api.groq.com/openai/v1"
			}

		case (strings.Contains(lowerModel, "nvidia") || strings.HasPrefix(model, "nvidia/")) && cfg.Providers.Nvidia.APIKey != "":
			apiKey = cfg.Providers.Nvidia.APIKey
			apiBase = cfg.Providers.Nvidia.APIBase
			proxy = cfg.Providers.Nvidia.Proxy
			if apiBase == "" {
				apiBase = "https://integrate.api.nvidia.com/v1"
			}
		case (strings.Contains(lowerModel, "ollama") || strings.HasPrefix(model, "ollama/")) && cfg.Providers.Ollama.APIKey != "":
			fmt.Println("Ollama provider selected based on model name prefix")
			apiKey = cfg.Providers.Ollama.APIKey
			apiBase = cfg.Providers.Ollama.APIBase
			proxy = cfg.Providers.Ollama.Proxy
			if apiBase == "" {
				apiBase = "http://localhost:11434/v1"
			}
			fmt.Println("Ollama apiBase:", apiBase)
		case (strings.Contains(lowerModel, "newapi") || strings.HasPrefix(model, "newapi/")) && cfg.Providers.NewAPI.APIKey != "":
			apiKey = cfg.Providers.NewAPI.APIKey
			apiBase = cfg.Providers.NewAPI.APIBase
			proxy = cfg.Providers.NewAPI.Proxy
			if apiBase == "" {
				apiBase = "https://newapi.sorai.me/v1"
			}
		case cfg.Providers.VLLM.APIBase != "":
			apiKey = cfg.Providers.VLLM.APIKey
			apiBase = cfg.Providers.VLLM.APIBase
			proxy = cfg.Providers.VLLM.Proxy

		default:
			if cfg.Providers.OpenRouter.APIKey != "" {
				apiKey = cfg.Providers.OpenRouter.APIKey
				proxy = cfg.Providers.OpenRouter.Proxy
				if cfg.Providers.OpenRouter.APIBase != "" {
					apiBase = cfg.Providers.OpenRouter.APIBase
				} else {
					apiBase = "https://openrouter.ai/api/v1"
				}
			} else {
				return nil, fmt.Errorf("no API key configured for model: %s", model)
			}
		}
	}

	if apiKey == "" && !strings.HasPrefix(model, "bedrock/") {
		return nil, fmt.Errorf("no API key configured for provider (model: %s)", model)
	}

	if apiBase == "" {
		return nil, fmt.Errorf("no API base configured for provider (model: %s)", model)
	}

	return NewHTTPProvider(apiKey, apiBase, proxy), nil
}
