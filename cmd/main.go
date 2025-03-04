package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/api"
	"github.com/daxtar2/Guts/pkg/mitm"
)

func main() {
	// 初始化配置
	config.InitConfig()

	// 创建证书目录
	certDir := filepath.Join(".", "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("创建证书目录失败: %v", err)
	}
	config.GConfig.CaConfig.CaRootPath = certDir

	// 创建API服务
	server := api.NewServer(config.RedisAddr)

	// 启动代理服务
	go func() {
		mitm.NewMitmproxy()
	}()

	// 启动API服务器
	log.Printf("Starting API server on :7080")
	if err := server.Run(":7080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
