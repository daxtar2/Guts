package util

import (
	"strings"

	re2 "github.com/wasilibs/go-re2"
)

func JudgeHostByRegex(domains []string, domain string) bool {
	for _, d := range domains {
		// 1. 精确匹配
		if d == domain {
			return true
		}

		// 2. 子域名匹配
		if strings.HasSuffix(domain, "."+d) {
			return true
		}

		// 3. 正则匹配 (保留原有功能)
		result, err := re2.MatchString(d, domain)
		if err != nil {
			continue
		}
		if result {
			return true
		}
	}
	return false
}
