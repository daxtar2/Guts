package test

import (
	"fmt"
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm"
	"os"
	"testing"
)

func TestMitmproxy(t *testing.T) {
	dir, _ := os.Getwd()
	fmt.Printf("当前工作目录: %s\n", dir)
	config.InitConfig()
	mitm.NewMitmproxy()
}
