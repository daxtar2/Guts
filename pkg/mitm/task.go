package main

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"strings"
)
var host string
func distrib(f *proxy.Flow) {
	parseUrl := f.Request.URL

	port := parseUrl.Port()
	if port == "" && (port == "80" || port == "443") {
		host = parseUrl.Hostname()
	} else {
		host = parseUrl.Host
	}

	headerMap := config.GConfig.HeaderMap {
		Headers: make(map[string]string,len(f.Request.Header)),
		SetCookie: nil,
	}

	for key,value := range f.Request.Header {
		if key == "Set-Cookie" {
			headerMap.SetCookie = append(headerMap.SetCookie, value...)
		}else {
			headerMap.Headers[key] = strings.Join(value, ",")
		}
	}

	re := &header.PassiveResult{
		Url: parseUrl.String(),
		Host: host,
	}

	t.Wg.Add(1)
	go func(data *header.PassiveResult) {
		defer t.Wg.Done()
		if err := t.Pool.Submit(t.)
	}

}
