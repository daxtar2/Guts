package main

import (
	"github.com/daxtar2/go-mitmproxy/proxy"
	"log"
)

type Proxy struct{}

func main() {
	opts := &proxy.Options{
		Addr:              ":7070",
		StreamLargeBodies: 1024 * 1024 * 5,
	}
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(p.Start())
}
