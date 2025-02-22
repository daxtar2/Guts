package test

import (
	"fmt"
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm"
	"os"
	"path/filepath"
	"testing"
)

func TestMitmproxy(t *testing.T) {
	dir, _ := os.Getwd()
	fmt.Printf("当前工作目录: %s\n", dir)
	config.InitConfig()

	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("创建证书目录失败: %v", err)
	}

	config.GConfig.CaConfig.CaRootPath = certDir

	mitm.NewMitmproxy()

	//time.Sleep(2 * time.Second)
}
