package mitm

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"go.uber.org/zap"
)

// 将Request 请求转换成存储成string
func ReqToString(req *proxy.Request) string {
	buf := new(bytes.Buffer) // 避免 make([]byte, 0)

	// 拼接请求行
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.URL.RequestURI())
	buf.WriteByte(' ')
	buf.WriteString(req.Proto)
	buf.WriteString("\r\n")

	// 添加 Host 头
	buf.WriteString("Host: ")
	buf.WriteString(req.URL.Host)
	buf.WriteString("\r\n")

	// 添加 Transfer-Encoding
	if len(req.Raw().TransferEncoding) > 0 {
		buf.WriteString("Transfer-Encoding: ")
		buf.WriteString(strings.Join(req.Raw().TransferEncoding, ","))
		buf.WriteString("\r\n")
	}

	// 添加 Connection: close
	if req.Raw().Close {
		buf.WriteString("Connection: close\r\n")
	}

	// 写入请求头
	if err := req.Header.WriteSubset(buf, nil); err != nil {
		logger.Error("写入请求头失败", zap.Error(err))
	}

	buf.WriteString("\r\n") // HTTP 头部结束

	// 添加请求体
	if req.Body != nil && len(req.Body) > 0 && canPrint(req.Body) {
		buf.Write(req.Body)
		buf.WriteString("\r\n\r\n")
	}

	return buf.String()
}

func RespToString(f *proxy.Flow) string {
	if f.Response == nil {
		return ""
	}

	buf := new(bytes.Buffer) // 避免多余的内存空间占用

	// 拼接状态行
	fmt.Fprintf(buf, "%s %d %s\r\n", f.Request.Proto, f.Response.StatusCode, http.StatusText(f.Response.StatusCode))

	// 写入响应头
	if err := f.Response.Header.WriteSubset(buf, nil); err != nil {
		logger.Error("写入响应头失败", zap.Error(err))
	}

	buf.WriteString("\r\n") // HTTP 头部结束

	// 解析并写入响应体
	if f.Response.Body != nil && len(f.Response.Body) > 0 {
		body, err := f.Response.DecodedBody()
		if err == nil && len(body) > 0 {
			buf.Write(body)
			buf.WriteString("\r\n\r\n")
		}
	}

	return buf.String()
}

func canPrint(content []byte) bool {
	for len(content) > 0 {
		r, size := utf8.DecodeRune(content)
		if r == utf8.RuneError {
			return false
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
		content = content[size:]
	}
	return true
}
