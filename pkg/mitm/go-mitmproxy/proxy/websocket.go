package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	log "github.com/sirupsen/logrus"
)

// 当前仅做了转�?websocket 流量
type webSocket struct{}

var defaultWebSocket webSocket

// WebsocketConn 处理WebSocket连接
type WebsocketConn struct {
	reader *bufio.Reader
	writer io.Writer
}

// NewWebsocketConn 创建新的WebSocket连接
func NewWebsocketConn(reader *bufio.Reader, writer io.Writer) *WebsocketConn {
	return &WebsocketConn{
		reader: reader,
		writer: writer,
	}
}

// HandleWebsocket 处理WebSocket通信
func (w *WebsocketConn) HandleWebsocket(req *http.Request) error {
	// 基本的WebSocket握手
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: 101,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}

	resp.Header.Set("Upgrade", "websocket")
	resp.Header.Set("Connection", "Upgrade")

	// 写入响应
	if err := resp.Write(w.writer); err != nil {
		return err
	}

	return nil
}

// ReadMessage 读取WebSocket消息
func (w *WebsocketConn) ReadMessage() ([]byte, error) {
	return nil, nil // 实际实现需要按WebSocket协议解析帧
}

// WriteMessage 写入WebSocket消息
func (w *WebsocketConn) WriteMessage(data []byte) error {
	return nil // 实际实现需要按WebSocket协议构造帧
}

func (s *webSocket) wss(res http.ResponseWriter, req *http.Request) {
	log := log.WithField("in", "webSocket.wss").WithField("host", req.Host)

	upgradeBuf, err := httputil.DumpRequest(req, false)
	if err != nil {
		log.Errorf("DumpRequest: %v\n", err)
		res.WriteHeader(502)
		return
	}

	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		log.Errorf("Hijack: %v\n", err)
		res.WriteHeader(502)
		return
	}
	defer cconn.Close()

	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		log.Errorf("tls.Dial: %v\n", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(upgradeBuf)
	if err != nil {
		log.Errorf("wss upgrade: %v\n", err)
		return
	}
	transfer(log, conn, cconn)
}
