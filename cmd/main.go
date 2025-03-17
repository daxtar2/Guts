package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/api"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm"
	"github.com/daxtar2/Guts/pkg/scan"
	"go.uber.org/zap"
)

func main() {
	// 1. 初始化日志系统
	if err := logger.InitLogger(); err != nil {
		log.Fatalf("初始化日志系统失败: %v", err)
	}
	defer logger.Log.Sync()

	// 2. 初始化配置
	if err := config.InitConfig(); err != nil {
		logger.Fatal("初始化配置失败", zap.Error(err))
	}
	logger.Info("配置初始化完成")

	// 3. 创建证书目录
	certDir := filepath.Join(".", "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		logger.Fatal("创建证书目录失败", zap.Error(err))
	}
	config.GConfig.CaConfig.CaRootPath = certDir

	// 4. 创建并启动API服务
	server := api.NewServer(config.GConfig.Redis.Address)
	logger.Info("API服务创建完成", zap.String("redis_addr", config.GConfig.Redis.Address))

	// 5. 启动代理服务（在后台运行）
	go func() {
		logger.Info("正在启动代理服务", zap.String("port", config.GConfig.Mitmproxy.AddrPort))
		mitm.NewMitmproxy()
	}()

	// 6. 创建扫描任务
	scanTask, err := scan.NewTask(100)
	if err != nil {
		logger.Fatal("创建扫描任务失败", zap.Error(err))
	}

	// 注册关闭处理
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Info("收到关闭信号，正在优雅退出...")
		if scanTask != nil {
			scanTask.Close()
		}
		logger.Info("扫描任务已关闭")
		os.Exit(0)
	}()

	// 7. 启动API服务器（主线程）
	logger.Info("正在启动API服务器", zap.String("port", ":7080"))
	if err := server.Run(":7080"); err != nil {
		logger.Fatal("启动API服务器失败", zap.Error(err))
	}
}
