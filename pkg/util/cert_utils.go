package util

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// InstallCACert 安装 CA 证书到系统信任列表
func InstallCACert(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		// Windows 系统使用 certutil 工具安装证书
		cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("安装证书失败: %v\n请以管理员权限运行或手动安装证书", err)
		}
	case "darwin":
		// macOS 系统使用 security 工具安装证书
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("安装证书失败: %v\n请使用 sudo 运行或手动安装证书", err)
		}
	case "linux":
		// Linux 系统需要复制证书到特定目录
		certDir := "/usr/local/share/ca-certificates/"
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return err
		}
		destPath := certDir + "mitmproxy-ca.crt"
		if err := copyFile(certPath, destPath); err != nil {
			return err
		}
		cmd := exec.Command("update-ca-certificates")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("更新证书失败: %v\n请使用 sudo 运行或手动安装证书", err)
		}
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
	return nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}
