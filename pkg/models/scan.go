package models

import (
	"net/http"
	"time"
)

// ScanResult 扫描结果
type ScanResult struct {
	ID          string    `json:"id"`          // 唯一标识
	Target      string    `json:"target"`      // 扫描目标
	Name        string    `json:"name"`        // 漏洞名称
	Severity    string    `json:"severity"`    // 严重程度
	Type        string    `json:"type"`        // 漏洞类型
	Host        string    `json:"host"`        // 影响主机
	MatchedAt   string    `json:"matched_at"`  // 匹配位置
	Description string    `json:"description"` // 漏洞描述
	Tags        []string  `json:"tags"`        // 标签
	Reference   []string  `json:"reference"`   // 参考链接
	Timestamp   time.Time `json:"timestamp"`   // 扫描时间
}

// PassiveResult 被动扫描结果
type PassiveResult struct {
	Url     string      `json:"url"`     // 请求url
	Host    string      `json:"host"`    // 主机
	Path    string      `json:"path"`    // 请求路径
	Method  string      `json:"method"`  // 请求方法
	Headers http.Header `json:"headers"` // 请求头
	Body    string      `json:"body"`    // 响应体
}
