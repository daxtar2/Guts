package helper

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
)

// 尝试�?Reader 读取�?buffer �?
// 如果未达�?limit，则成功读取进入 buffer
// 否则 buffer 返回 nil，且返回�?Reader，状态为未读取前
func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	// 达到上限
	if int64(buf.Len()) == limit {
		// 返回新的 Reader
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	// 返回 buffer
	return buf.Bytes(), nil, nil
}

func NewStructFromFile(filename string, v interface{}) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// CanonicalAddr returns url.Host but always with a ":port" suffix.
func CanonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(url.Hostname(), port)
}

// https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py is_tls_record_magic
func IsTls(buf []byte) bool {
	if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03 {
		return true
	} else {
		return false
	}
}

type ResponseCheck struct {
	http.ResponseWriter
	Wrote bool
}

func NewResponseCheck(r http.ResponseWriter) http.ResponseWriter {
	return &ResponseCheck{
		ResponseWriter: r,
	}
}

func (r *ResponseCheck) WriteHeader(statusCode int) {
	r.Wrote = true
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *ResponseCheck) Write(bytes []byte) (int, error) {
	r.Wrote = true
	return r.ResponseWriter.Write(bytes)
}
