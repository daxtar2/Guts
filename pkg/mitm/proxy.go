package mitm

import (
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"log"
)

func Mitmproxy() {
	opts := &proxy.Options{
		Addr:              ":7777",
		StreamLargeBodies: 1024 * 1024 * 5,
	}
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(p.Start())
}
