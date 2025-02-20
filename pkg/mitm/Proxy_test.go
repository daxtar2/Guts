package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/daxtar2/Guts/config"
	"github.com/stretchr/testify/assert"
)

func TestPassiveProxyOn8080(t *testing.T) {
	var wg sync.WaitGroup

	// 保存原始配置，测试完成后恢复，避免污染其他测试
	originalPort := config.GConfig.Mitmproxy.AddrPort
	config.GConfig.Mitmproxy.AddrPort = ":8080" // 设置代理监听端口
	defer func() { config.GConfig.Mitmproxy.AddrPort = originalPort }()

	// 启动代理
	mitmProxy := NewMitmproxy()
	wg.Add(1) // 增加 WaitGroup 计数器
	go func() {
		defer wg.Done() // 测试结束时减少计数器
		if err := mitmProxy.Start(); err != nil {
			t.Fatalf("代理启动失败: %v", err)
		}
	}()
	defer mitmProxy.Close() // 确保测试完成后关闭代理

	// 等待代理完全启动
	time.Sleep(1 * time.Second)

	// 创建一个本地服务器，模拟被代理的目标流量
	testServerAddr := "localhost:8081"
	go func() {
		http.ListenAndServe(testServerAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, proxy!"))
		}))
	}()
	time.Sleep(1 * time.Second) // 确保测试服务器启动

	// 使用 HTTP 客户端通过代理发送请求
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "localhost:8080"}), // 设置代理为 8080
		},
	}
	resp, err := client.Get("http://" + testServerAddr)
	assert.NoError(t, err, "代理请求出错")
	assert.NotNil(t, resp, "响应为空")
	defer resp.Body.Close()

	// 验证代理响应
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err, "读取响应体出错")
	assert.Equal(t, "Hello, proxy!", string(body), "代理未正确转发流量")

	// 等待所有 goroutine 退出
	wg.Wait()
}
