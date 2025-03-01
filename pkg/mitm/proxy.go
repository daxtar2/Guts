package mitm

import (
	"log"
	"os"
	"path/filepath"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/cert"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/daxtar2/Guts/pkg/util"
)

func NewMitmproxy() {
	certDir := config.GConfig.CaConfig.CaRootPath

	// 确保证书目录存在
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("创建证书目录失败: %v", err)
	}

	// 使用 NewSelfSignCA 来处理证书的加载或创建
	ca, err := cert.NewSelfSignCA(certDir)
	if err != nil {
		log.Fatalf("证书初始化失败: %v", err)
	}

	// 如果是新生成的证书，尝试安装到系统信任列表
	certFile := filepath.Join(certDir, "mitmproxy-ca-cert.pem")
	if _, err := os.Stat(certFile); err == nil {
		if err := util.InstallCACert(certFile); err != nil {
			log.Printf("警告: 自动安装证书失败，请手动安装证书: %v", err)
			log.Printf("证书路径: %s", certFile)
			log.Printf("Windows 用户请双击 %s 安装证书到 '受信任的根证书颁发机构'",
				filepath.Join(certDir, "mitmproxy-ca-cert.cer"))
		}
	}

	// 创建全局扫描任务
	globalTask, err := scan.NewTask(30)
	if err != nil {
		log.Fatalf("创建扫描任务失败: %v", err)
	}
	globalTask.Wg.Add(1) // 堵塞进程，防止提前退出

	opts := &proxy.Options{
		Debug:             0,
		Addr:              config.GConfig.Mitmproxy.AddrPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       true,
		CaRootPath:        certDir,
		NewCaFunc:         func() (cert.CA, error) { return ca, nil },
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	infoAddon := NewInfoAddon(config.GConfig, globalTask, config.GConfig.Mitmproxy.FilterSuffix)
	p.AddAddon(infoAddon)
	go func() {
		err = p.Start()
		if err != nil {
			log.Fatal(err)
		}
	}()
	globalTask.Wg.Wait()
}
