package mitm

import (
	"path/filepath"

	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/daxtar2/Guts/pkg/util"
	"github.com/thoas/go-funk"
)

type InfoAddon struct {
	proxy.BaseAddon
	config     *models.Config
	task       *scan.Task
	filterList []string
}

// 添加配置更新通道
var configUpdateChan = make(chan models.MitmproxyConfig, 1)

// 更新配置的方法
func UpdateConfig(newConfig models.MitmproxyConfig) {
	configUpdateChan <- newConfig
}

// 判断域名黑白名单
func isDomainAllowed(f *proxy.Flow) bool {
	host := f.Request.URL.Host
	cfg := config.GConfig.Mitmproxy

	if len(cfg.IncludeDomain) > 0 && !(len(cfg.IncludeDomain) == 1 && cfg.IncludeDomain[0] == "") { // if blacklist not
		if util.JudgeHostByRegex(cfg.IncludeDomain, host) {
			return true // traffic allowed
		}
	} else {
		if len(cfg.ExcludeDomain) > 0 && !(len(cfg.ExcludeDomain) == 1 && cfg.ExcludeDomain[0] == "") {
			if util.JudgeHostByRegex(cfg.ExcludeDomain, host) {
				return false
			}
		} else {
			return true
		}
	}
	return false
}

// 从后缀判断文件类型
func isSuffixAllowed(f *proxy.Flow) bool {
	ext := filepath.Ext(f.Request.URL.Path)
	return ext == "" || !funk.Contains(config.GConfig.Mitmproxy.FilterSuffix, ext)
}

func NewInfoAddon(config *models.Config, task *scan.Task, filterList []string) *InfoAddon {
	return &InfoAddon{
		config:     config,
		task:       task,
		filterList: filterList,
	}
}

func (IA *InfoAddon) Response(f *proxy.Flow) {
	// 非阻塞方式检查配置更新
	select {
	case newConfig := <-configUpdateChan:
		config.GConfig.Mitmproxy = newConfig
	default:
	}

	if f.Request.Method == "CONNECT" {
		return
	} //skip CONNECT request
	if isDomainAllowed(f) && isSuffixAllowed(f) { // total white host
		distrib(f, IA.task)
	}
}

func SomeFunction(newConfig models.MitmproxyConfig) {
	// 使用 newConfig
}
