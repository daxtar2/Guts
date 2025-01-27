package main

import (
	"fmt"
	"strings"

	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
)

var host string

func distrib(f *proxy.Flow) {
	parseUrl := f.Request.URL

	//避免端口干扰
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
	var err error
	if f.Response != nil {
		body, err = f.Response.DecodedBody()
		if err != nil {
			// 记录解码错误但继续处理
			fmt.Printf("Failed to decode response body: %v\n", err)
			body = f.Response.Body
		}
	}

	headerMap := make(map[string]string)
	for key, value := range f.Request.Header {
		if key == "Set-Cookie" {
			headerMap[key] = strings.Join(value, ";")
		} else {
			headerMap[key] = strings.Join(value, ",")
		}
	}

	scanInput := &header.PassiveResult{
		Url:      parseUrl.String(),
		ParseUrl: parseUrl,
		Host:     host,
		//status
		Method:       f.Request.Method,
		Headers:      headerMap,
		RequestBody:  string(f.Request.Body),
		ContentType:  f.Request.Header.Get("Content-Type"),
		RawRequest:   ReqToString(f.Request),
		RawResponse:  RespToString(f),
		ResponseBody: string(body), // 添加响应体
	}

	PrintInfo(scanInput)

	// t.Wg.Add(1)
	// go func(data *header.PassiveResult) {
	// 	defer t.Wg.Done()
	// 	if err := t.Pool.Submit(t.ScanBegin(scanInput)); err != nil {
	// 		panic(err)
	// 	}
	// }(scanInput)

}

func PrintInfo(scanInput *header.PassiveResult) {
	fmt.Println(scanInput)
}
