package mitm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/daxtar2/Guts/pkg/header"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
)

var (
	// 用于去重的map
	scannedHosts = sync.Map{} //域名去重
)

func distrib(f *proxy.Flow, task *scan.Task) {
	parseUrl := f.Request.URL

	// 处理域名
	host := parseUrl.Hostname()

	// 检查是否已经扫描过该域名
	if _, exists := scannedHosts.LoadOrStore(host, true); exists {
		return // 如果已经扫描过，直接返回
	}

	// 构建请求头映射
	headerMap := make(map[string]string)
	for key, value := range f.Request.Header {
		if key == "Set-Cookie" {
			headerMap[key] = strings.Join(value, ";")
		} else {
			headerMap[key] = strings.Join(value, ",")
		}
	}

	//// 获取响应体
	//if f.Response != nil {
	//	_, err := f.Response.DecodedBody()
	//	if err != nil {
	//		fmt.Printf("Failed to decode response body: %v\n", err)
	//	}
	//}

	// 构建扫描输入
	scanInput := &header.PassiveResult{
		Url:         parseUrl.String(),
		ParseUrl:    parseUrl,
		Host:        host,
		Method:      f.Request.Method,
		Headers:     headerMap,
		RequestBody: string(f.Request.Body),
		ContentType: f.Request.Header.Get("Content-Type"),
		RawRequest:  ReqToString(f.Request),
		RawResponse: RespToString(f),
	}

	// 使用传入的 task 执行扫描
	go func(input *header.PassiveResult) {
		if err := task.ScanPassiveResult(input); err != nil {
			fmt.Printf("域名扫描失败 [%s]: %v\n", input.Host, err)
		}
	}(scanInput)
}

//func PrintInfo(scanInput *header.PassiveResult) {
//	fmt.Println(scanInput)
//}
