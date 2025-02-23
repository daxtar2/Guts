package mitm

import (
	"log"
	"os"
	"sync"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/cert"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
)

func NewMitmproxy() {
	certDir := config.GConfig.CaConfig.CaRootPath
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("创建证书目录失败: %v", err)
	}
	// 2. 生成或加载 CA 证书
	ca, err := cert.NewSelfSignCA(certDir)
	if err != nil {
		log.Fatalf("CA 证书生成失败: %v", err)
	}

	opts := &proxy.Options{
		Debug:             0,
		Addr:              config.GConfig.Mitmproxy.AddrPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       true,
		CaRootPath:        certDir,
		NewCaFunc:         func() (cert.CA, error) { return ca, nil },
	}
	t := &scan.Task{
		MaxPoolsize: 10,
		Wg:          &sync.WaitGroup{},
	}
	t.Wg.Add(1) //堵塞进程，防止提前退出

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	infoAddon := NewInfoAddon(config.GConfig, t, config.GConfig.Mitmproxy.FilterSuffix) //实例化addon
	p.AddAddon(infoAddon)                                                               //添加addon
	go func() {
		err = p.Start()
		if err != nil {
			log.Fatal(err)
		}
	}()
	t.Wg.Wait()
}
