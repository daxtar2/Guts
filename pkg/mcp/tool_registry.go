// Package mcp 实现 Model Context Protocol (MCP) 工具注册与管理。
package mcp

import (
	"context"
	"fmt"
	"sync"
)

// ToolInput MCP 工具输入参数
type ToolInput map[string]interface{}

// ToolOutput MCP 工具输出结果
type ToolOutput struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

// ToolHandler MCP 工具处理函数
type ToolHandler func(ctx context.Context, input ToolInput) (*ToolOutput, error)

// ToolDefinition MCP 工具定义
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
	Handler     ToolHandler            `json:"-"`
}

// ToolRegistry MCP 工具注册表
type ToolRegistry struct {
	mu    sync.RWMutex
	tools map[string]*ToolDefinition
}

// NewToolRegistry 创建工具注册表
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]*ToolDefinition),
	}
}

// Register 注册工具
func (r *ToolRegistry) Register(tool *ToolDefinition) error {
	if tool.Name == "" {
		return fmt.Errorf("工具名称不能为空")
	}
	if tool.Handler == nil {
		return fmt.Errorf("工具 %s 缺少处理函数", tool.Name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name] = tool
	return nil
}

// Execute 执行已注册的工具
func (r *ToolRegistry) Execute(ctx context.Context, toolName string, input ToolInput) (*ToolOutput, error) {
	r.mu.RLock()
	tool, exists := r.tools[toolName]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("工具 %s 未注册", toolName)
	}

	return tool.Handler(ctx, input)
}

// ListTools 列出所有已注册工具的名称和描述
func (r *ToolRegistry) ListTools() []map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]map[string]string, 0, len(r.tools))
	for _, tool := range r.tools {
		result = append(result, map[string]string{
			"name":        tool.Name,
			"description": tool.Description,
		})
	}
	return result
}
