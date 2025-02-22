package mitm

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"log"
	"sync"
)

func NewMitmproxy() {
	opts := &proxy.Options{
		Debug:             0,
		Addr:              config.GConfig.Mitmproxy.AddrPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       true,
	}
	t := &scan.Task{
		MaxPoolsize: 10,
		Wg:          &sync.WaitGroup{},
	}
	//t, err := scan.NewTask(10)
	//if err != nil {
	//	log.Fatal(err)
	//}
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
