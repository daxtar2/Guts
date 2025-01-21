package header

import "net/url"

type PassiveResult struct {
	Url         string            `json:"url"`
	ParseUrl    *url.URL          `json:"parse_url"`
	Host        string            `json:"host"`
	Port        string            `json:"port"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	RequestBody string            `json:"request_body"`
	ContentType string            `json:"content_type"`
	RawRequest  string            `json:"raw_request"`
	RawResponse string            `json:"raw_response"`
}
