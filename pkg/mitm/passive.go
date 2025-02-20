package main

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/daxtar2/Guts/pkg/scan"
	"github.com/daxtar2/Guts/pkg/util"
	"path/filepath"
	"sync"
)

type InfoAddon struct {
	proxy.BaseAddon
	cfg           *config.Config
	scanTask      *scan.Task
	domainCache   sync.Map        //缓存域名白名单的检查结果
	excludeSuffix map[string]bool //待过滤的后缀哈希表
}

func NewInfoAddon(cfg *config.Config, scanTask *scan.Task, excludeSuffix []string) *InfoAddon {
	excludeSuffixMap := make(map[string]bool)
	for _, ext := range excludeSuffix {
		excludeSuffixMap[ext] = true
	}
	return &InfoAddon{
		cfg:           cfg,
		scanTask:      scanTask,
		excludeSuffix: excludeSuffixMap,
	}
}

// 判断域名黑白名单
func (IA *InfoAddon) isDomainAllowed(f *proxy.Flow) bool {
	host := f.Request.URL.Host

	if allowed, ok := IA.domainCache.Load(host); ok {
		return allowed.(bool)
	}
	var allowed bool
	if len(IA.cfg.Mitmproxy.IncludeDomain) > 0 {
		allowed = util.JudgeHostByRegex(IA.cfg.Mitmproxy.IncludeDomain, host)
	} else if len(IA.cfg.Mitmproxy.ExcludeDomain) > 0 {
		allowed = util.JudgeHostByRegex(IA.cfg.Mitmproxy.ExcludeDomain, host)
	} else {
		allowed = true
	}
	IA.domainCache.Store(host, allowed)
	return allowed
}

// 从后缀判断文件类型
func (IA *InfoAddon) isSuffixAllowed(f *proxy.Flow) bool {
	ext := filepath.Ext(f.Request.URL.Path)
	if ext == "" {
		return true
	}
	return !IA.excludeSuffix[ext]
}

func (IA *InfoAddon) Response(trafficF *proxy.Flow) {
	if trafficF.Request.Method == "CONNECT" {
		return
	} //skip CONNECT request
	if IA.isDomainAllowed(trafficF) && IA.isSuffixAllowed(trafficF) { // total white host
		distrib(trafficF, IA.scanTask)
	}
}
