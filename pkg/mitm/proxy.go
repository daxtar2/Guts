package main

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"log"
)

var t *scan.Task

func NewMitmproxy() {
	opts := &proxy.Options{
		Debug:             0,
		Addr:              config.GConfig.Mitmproxy.AddrPort,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.GConfig.Mitmproxy.SslInsecure,
	}
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}
	p.AddAddon(&InfoAddon{})
	go func() {
		err := p.Start()
		if err != nil {
			log.Fatal(err)
		}
	}()
	t.Wg.Wait()

}
