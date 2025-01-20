package main

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/mitm/go-mitmproxy/proxy"
	"github.com/thoas/go-funk"
	"path/filepath"
)

type InfoAddon struct {
	proxy.BaseAddon
}

func isDomainAllowed(f *proxy.Flow) bool {
	host := f.Request.URL.Host
	cfg := config.GConfig.Mitmproxy

	if len(cfg.IncludeDomain) > 0 && !(len(cfg.IncludeDomain) == 1 && cfg.IncludeDomain[0] == "") { // if blacklist not
		if util.Regexp(cfg.IncludeDomain, host) {
			return true // traffic allowed
		}
	} else {
		if len(cfg.ExcludeDomain) > 0 && !(len(cfg.ExcludeDomain) == 1 && cfg.ExcludeDomain[0] == "") {
			if util.Regexp(cfg.ExcludeDomain, host) {
				return false
			}
		} else {
			return true
		}
	}
}

func isSuffixAllowed(f *proxy.Flow) bool {
	ext := filepath.Ext(f.Request.URL.Path)
	return ext == "" || !funk.Contains(config.GConfig.Mitmproxy.FilterSufffix, ext)
}

func (IA *InfoAddon) Response(trafficF *proxy.Flow) {
	if trafficF.Request.Method == "CONNECT" {
		return
	} //skip CONNECT request
	if isDomainAllowed(trafficF) && isSuffixAllowed(trafficF) { // total white host
		distribution(trafficF)
	}
}
