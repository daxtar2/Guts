package util

import (
	"fmt"
	"os/exec"
	"runtime"
)

// InstallCACert 安装 CA 证书到系统信任列表
func InstallCACert(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("certutil", "-addstore", "ROOT", certPath)
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
		return cmd.Run()
	case "linux":
		// Linux 系统需要根据不同发行版采取不同方式
		return fmt.Errorf("请手动安装证书: %s", certPath)
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}
