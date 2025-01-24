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

	//headerMap := config.GConfig.HeaderMap
	//{
	//	Headers: make(map[string]string,len(f.Request.Header)),
	//	SetCookie: nil
	//}

	var body []byte
	body ,err := f.Response.DecodedBody()
	if err != nil { body = f.Response.Body}

	headerMap := make(map[string]string)
	for key,value := range f.Request.Header {
		if key == "Set-Cookie" {
			headerMap[key] = strings.Join(value, ";")
		}else {
			headerMap[key] = strings.Join(value, ",")
		}
	}

	scanInput := &header.PassiveResult{
		Url: parseUrl.String(),
		ParseUrl: parseUrl,
		Host: host,
		//status
		Method: f.Request.Method,
		Headers: headerMap,
		RequestBody: string(f.Request.Body),
		ContentType: f.Request.Header.Get("Content-Type"),
		RawRequest: ReqToString(f.Request),
		RawResponse: RespToString(f),
	}

	t.Wg.Add(1)
	go func(data *header.PassiveResult) {
		defer t.Wg.Done()
		if err := t.Pool.Submit(t.ScanBegin(scanInput))
	}

}
