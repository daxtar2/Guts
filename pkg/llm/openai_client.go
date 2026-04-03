package llm

import (
	"context"
	"fmt"

	"github.com/sashabaranov/go-openai"
)

// OpenAIConfig OpenAI 客户端配置
type OpenAIConfig struct {
	APIKey  string `mapstructure:"api_key"`
	BaseURL string `mapstructure:"base_url"` // 可替换为 Ollama 等兼容端点
	Model   string `mapstructure:"model"`
}

// OpenAIClient LLM 客户端封装
type OpenAIClient struct {
	client *openai.Client
	config OpenAIConfig
}

// NewOpenAIClient 创建新的 LLM 客户端
func NewOpenAIClient(cfg OpenAIConfig) *OpenAIClient {
	clientConfig := openai.DefaultConfig(cfg.APIKey)
	if cfg.BaseURL != "" {
		clientConfig.BaseURL = cfg.BaseURL
	}
	if cfg.Model == "" {
		cfg.Model = openai.GPT4
	}
	return &OpenAIClient{
		client: openai.NewClientWithConfig(clientConfig),
		config: cfg,
	}
}

// ChatCompletion 发送对话补全请求
func (c *OpenAIClient) ChatCompletion(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.config.Model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
	})
	if err != nil {
		return "", fmt.Errorf("LLM 请求失败: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("LLM 返回空响应")
	}
	return resp.Choices[0].Message.Content, nil
}
