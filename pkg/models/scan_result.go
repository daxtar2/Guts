package models

type ScanResult struct {
	ID         string `json:"id"`          // 扫描结果的唯一标识
	Host       string `json:"host"`        // 扫描的主机
	VulnName   string `json:"vuln_name"`   // 漏洞名称
	Severity   string `json:"severity"`    // 漏洞严重程度
	CreateTime string `json:"create_time"` // 创建时间
	Details    string `json:"details"`     // 详细信息
}
