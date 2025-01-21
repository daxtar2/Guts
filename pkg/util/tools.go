package util

import (
	re2 "github.com/wasilibs/go-re2"
)

func JudgeHostByRegex(domains []string, domain string) bool { //
	for _, d := range domains {
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
