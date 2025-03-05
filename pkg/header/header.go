package header

import (
	"net/url"
	"time"
)

type PassiveResult struct {
	Url          string              `json:"url"`
	ParseUrl     *url.URL            `json:"parse_url"`
	Host         string              `json:"host"`
	Port         string              `json:"port"`
	status       int                 `json:"status"` // 用于判断目标是否被扫描过
	Method       string              `json:"method"`
	Headers      map[string]string   `json:"headers"`
	RequestBody  string              `json:"request_body"`
	ContentType  string              `json:"content_type"`
	RawRequest   string              `json:"raw_request"`
	RawResponse  string              `json:"raw_response"`
	ResponseBody string              `json:"response_body"`
	TechStack    map[string][]string `json:"tech_stack"`
	StatusCode   int                 `json:"status_code"`
	Body         []byte              `json:"body"`
	Timestamp    time.Time           `json:"timestamp"`
	SessionID    string              `json:"session_id"`
}
