package util

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/daxtar2/Guts/pkg/logger"
	"go.uber.org/zap"
)

// InstallCACert 安装 CA 证书到系统信任列表
func InstallCACert(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		// Windows 系统使用 certutil 工具安装证书
		cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath)
		if err := cmd.Run(); err != nil {
			logger.Error("安装证书失败", zap.Error(err))
			return err
		}
	case "darwin":
		// macOS 系统使用 security 工具安装证书
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
		if err := cmd.Run(); err != nil {
			logger.Error("安装证书失败", zap.Error(err))
			return err
		}
	case "linux":
		// Linux 系统需要复制证书到特定目录
		certDir := "/usr/local/share/ca-certificates/"
		if err := os.MkdirAll(certDir, 0755); err != nil {
			logger.Error("创建证书目录失败", zap.Error(err))
			return err
		}
		destPath := certDir + "mitmproxy-ca.crt"
		if err := copyFile(certPath, destPath); err != nil {
			logger.Error("复制证书失败", zap.Error(err))
			return err
		}
		cmd := exec.Command("update-ca-certificates")
		if err := cmd.Run(); err != nil {
			logger.Error("更新证书失败", zap.Error(err))
			return err
		}
	default:
		logger.Error("不支持的操作系统", zap.String("os", runtime.GOOS))
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
	return nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		logger.Error("读取证书失败", zap.Error(err))
		return err
	}
	return os.WriteFile(dst, input, 0644)
}
