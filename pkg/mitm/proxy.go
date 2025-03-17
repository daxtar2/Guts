package mitm

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/daxtar2/Guts/pkg/util"
	"go.uber.org/zap"
)

func NewMitmproxy() error {

	certDir := config.GConfig.CaConfig.CaRootPath

	// 确保证书目录存在
	if err := os.MkdirAll(certDir, 0755); err != nil {
		logger.Error("创建证书目录失败", zap.Error(err))
	}

	// 使用 NewSelfSignCA 来处理证书的加载或创建
	// ca, err := cert.NewSelfSignCA(certDir)
	// if err != nil {
	// 	logger.Error("证书初始化失败", zap.Error(err))
	// }

	// 如果是新生成的证书，尝试安装到系统信任列表
	certFile := filepath.Join(certDir, "mitmproxy-ca-cert.pem")
	if _, err := os.Stat(certFile); err == nil {
		if err := util.InstallCACert(certFile); err != nil {
			logger.Info("警告: 自动安装证书失败，请手动安装证书:", zap.Error(err))
			logger.Info("证书路径:", zap.String("certFile", certFile))
			//logger.Info("Windows 用户请双击 %s 安装证书到 '受信任的根证书颁发机构'",filepath.Join(certDir, "mitmproxy-ca-cert.cer"))
		}
	}

	// 创建全局扫描任务
	globalTask, err := scan.NewTask(30)
	if err != nil {
		logger.Error("创建扫描任务失败", zap.Error(err))
		return fmt.Errorf("创建扫描任务失败: %v", err)
	}
	globalTask.Wg.Add(1) // 堵塞进程，防止提前退出

	// 获取代理端口配置
	proxyPort := config.GConfig.Mitmproxy.AddrPort
	if proxyPort == "" {
		proxyPort = ":7777" // 添加默认端口
		logger.Info("使用默认端口", zap.String("port", proxyPort))
	}

	logger.Info("正在启动代理服务", zap.String("port", proxyPort))

	opts := &proxy.Options{
		//Debug:             0,
		Addr:              proxyPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       true,
		CaRootPath:        certDir,
		//NewCaFunc:         func() (cert.CA, error) { return ca, nil },
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		logger.Error("创建代理失败", zap.Error(err))
	}

	infoAddon := NewInfoAddon(config.GConfig, globalTask, config.GConfig.Mitmproxy.FilterSuffix)
	p.AddAddon(infoAddon)

	// 启动代理服务器
	go func() {
		if err := p.Start(); err != nil {
			logger.Error("启动代理失败", zap.Error(err))
		}
	}()

	globalTask.Wg.Wait()

	return nil
}
