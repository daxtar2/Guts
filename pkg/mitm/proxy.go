package mitm

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"go.uber.org/zap"
)

// NewMitmproxy 创建新的代理服务
func NewMitmproxy() error {
	// 创建全局扫描任务
	task, err := scan.NewTask(config.GConfig)
	if err != nil {
		logger.Error("创建扫描任务失败", zap.Error(err))
		return fmt.Errorf("创建扫描任务失败: %v", err)
	}
	task.Wg.Add(1) // 堵塞进程，防止提前退出

	// 获取代理端口配置
	proxyPort := config.GConfig.Mitmproxy.AddrPort
	if proxyPort == "" {
		proxyPort = ":7777" // 添加默认端口
		logger.Info("使用默认端口", zap.String("port", proxyPort))
	}

	logger.Info("正在启动代理服务", zap.String("port", proxyPort))

	// 设置代理选项
	opts := &proxy.Options{
		Addr:              proxyPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.GConfig.Mitmproxy.SslInsecure,
	}

	// 创建代理服务器
	p, err := proxy.NewProxy(opts)
	if err != nil {
		logger.Error("创建代理失败", zap.Error(err))
		return fmt.Errorf("创建代理服务器失败: %v", err)
	}

	// 添加流量输出 addon
	infoAddon := newInfoAddon(config.GConfig, task, config.GConfig.Mitmproxy.FilterSuffix)
	p.AddAddon(infoAddon)

	// 启动代理服务器
	go func() {
		if err := p.Start(); err != nil {
			logger.Error("代理服务器启动失败", zap.Error(err))
		}
	}()

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// 优雅关闭
	p.Close()
	task.Wg.Done()
	return nil
}
