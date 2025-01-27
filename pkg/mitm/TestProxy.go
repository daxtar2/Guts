package main

import (
	"testing"

	"github.com/daxtar2/Guts/config"
	// "github.com/daxtar2/Guts/config"
	// "github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	// "github.com/stretchr/testify/assert"
)

func TestPassiveProxy(t *testing.T) {
	config.GConfig.Mitmproxy.AddrPort = ":8080"
	NewMitmproxy()
}

// 			ExcludeDomain: []string{"excluded.com"},
// 			FilterSufffix: []string{".jpg", ".png", ".css"},
// 		},
// 	}

// 	// 测试Response方法的流量过滤
// 	t.Run("Test Response Flow Filtering", func(t *testing.T) {
// 		testCases := []struct {
// 			name        string
// 			method      string
// 			url         string
// 			description string
// 		}{
// 			{
// 				name:        "CONNECT Request Should Skip",
// 				method:      "CONNECT",
// 				url:         "https://example.com",
// 				description: "CONNECT requests should be skipped",
// 			},
// 			{
// 				name:        "Allowed Domain with Valid Suffix",
// 				method:      "GET",
// 				url:         "https://example.com/api/data.json",
// 				description: "Should process request with allowed domain and non-filtered suffix",
// 			},
// 			{
// 				name:        "Allowed Domain with Filtered Suffix",
// 				method:      "GET",
// 				url:         "https://example.com/image.jpg",
// 				description: "Should skip request with filtered suffix",
// 			},
// 			{
// 				name:        "Excluded Domain",
// 				method:      "GET",
// 				url:         "https://excluded.com/api/data",
// 				description: "Should skip request from excluded domain",
// 			},
// 			{
// 				name:        "Other Domain with Include List Set",
// 				method:      "GET",
// 				url:         "https://other.com/api/data",
// 				description: "Should skip request from non-included domain",
// 			},
// 		}

// 		for _, tc := range testCases {
// 			t.Run(tc.name, func(t *testing.T) {
// 				// 创建测试Flow
// 				parsedURL, _ := url.Parse(tc.url)
// 				flow := &proxy.Flow{
// 					Request: &proxy.Request{
// 						Method: tc.method,
// 						URL:    parsedURL,
// 						Header: make(http.Header),
// 					},
// 					Response: &proxy.Response{
// 						StatusCode: 200,
// 						Header:     make(http.Header),
// 						Body:       []byte("test response"),
// 					},
// 				}

// 				// 创建InfoAddon实例并调用Response方法
// 				addon := &InfoAddon{}
// 				addon.Response(flow)
// 			})
// 		}
// 	})

// 	// 测试边界情况
// 	t.Run("Test Edge Cases", func(t *testing.T) {
// 		testCases := []struct {
// 			name          string
// 			includeDomain []string
// 			excludeDomain []string
// 			url           string
// 			description   string
// 		}{
// 			{
// 				name:          "Empty Include Domain List",
// 				includeDomain: []string{""},
// 				excludeDomain: []string{"excluded.com"},
// 				url:           "https://example.com/test.html",
// 				description:   "Should process when include list is empty and domain not excluded",
// 			},
// 			{
// 				name:          "Empty Exclude Domain List",
// 				includeDomain: []string{"example.com"},
// 				excludeDomain: []string{""},
// 				url:           "https://example.com/test.html",
// 				description:   "Should process when domain is included and exclude list is empty",
// 			},
// 			{
// 				name:          "Both Domain Lists Empty",
// 				includeDomain: []string{""},
// 				excludeDomain: []string{""},
// 				url:           "https://example.com/test.html",
// 				description:   "Should process when both lists are empty",
// 			},
// 		}

// 		for _, tc := range testCases {
// 			t.Run(tc.name, func(t *testing.T) {
// 				// 临时修改配置
// 				originalInclude := config.GConfig.Mitmproxy.IncludeDomain
// 				originalExclude := config.GConfig.Mitmproxy.ExcludeDomain
// 				config.GConfig.Mitmproxy.IncludeDomain = tc.includeDomain
// 				config.GConfig.Mitmproxy.ExcludeDomain = tc.excludeDomain
// 				defer func() {
// 					config.GConfig.Mitmproxy.IncludeDomain = originalInclude
// 					config.GConfig.Mitmproxy.ExcludeDomain = originalExclude
// 				}()

// 				parsedURL, _ := url.Parse(tc.url)
// 				flow := &proxy.Flow{
// 					Request: &proxy.Request{
// 						Method: "GET",
// 						URL:    parsedURL,
// 						Header: make(http.Header),
// 					},
// 					Response: &proxy.Response{
// 						StatusCode: 200,
// 						Header:     make(http.Header),
// 						Body:       []byte("test response"),
// 					},
// 				}

// 				addon := &InfoAddon{}
// 				addon.Response(flow)
// 			})
// 		}
// 	})
// }

// // 测试辅助函数
// func TestHelperFunctions(t *testing.T) {
// 	t.Run("Test canPrint", func(t *testing.T) {
// 		testCases := []struct {
// 			name     string
// 			input    []byte
// 			expected bool
// 		}{
// 			{
// 				name:     "Printable ASCII",
// 				input:    []byte("Hello World"),
// 				expected: true,
// 			},
// 			{
// 				name:     "Non-printable bytes",
// 				input:    []byte{0x00, 0x01, 0x02},
// 				expected: false,
// 			},
// 		}

// 		for _, tc := range testCases {
// 			t.Run(tc.name, func(t *testing.T) {
// 				result := canPrint(tc.input)
// 				assert.Equal(t, tc.expected, result)
// 			})
// 		}
// 	})
// }
