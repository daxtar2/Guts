package models

import "time"

// ChainType 漏洞链类型
type ChainType string

const (
	ChainTypeInfoLeak    ChainType = "info_leak"      // 信息泄露链
	ChainTypePrivEsc     ChainType = "priv_esc"        // 权限提升链
	ChainTypeLateral     ChainType = "lateral_move"    // 横向移动链
	ChainTypeRCE         ChainType = "rce"             // 远程代码执行链
	ChainTypeDataExfil   ChainType = "data_exfil"      // 数据泄露链
	ChainTypeCredReuse   ChainType = "cred_reuse"      // 凭据复用链
)

// ChainNodeStatus 链路节点状态
type ChainNodeStatus string

const (
	ChainNodePending   ChainNodeStatus = "pending"
	ChainNodeActive    ChainNodeStatus = "active"
	ChainNodeCompleted ChainNodeStatus = "completed"
	ChainNodeFailed    ChainNodeStatus = "failed"
	ChainNodeSkipped   ChainNodeStatus = "skipped"
)

// ChainNode 漏洞链中的单个节点
type ChainNode struct {
	NodeID      string          `json:"node_id"`
	VulnID      string          `json:"vuln_id"`      // 关联的漏洞ID
	Action      string          `json:"action"`        // 执行的操作
	Status      ChainNodeStatus `json:"status"`
	Input       map[string]interface{} `json:"input"`  // 输入参数（可包含前节点提取的凭据）
	Output      map[string]interface{} `json:"output"` // 输出结果
	ExecutedAt  *time.Time      `json:"executed_at"`
}

// VulnerabilityChain 漏洞利用链
type VulnerabilityChain struct {
	ID            string      `json:"id"`
	SessionID     string      `json:"session_id"`
	Type          ChainType   `json:"type"`
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Nodes         []ChainNode `json:"nodes"`         // 链路节点（有序）
	RiskScore     float64     `json:"risk_score"`    // 综合风险评分
	Exploitability float64    `json:"exploitability"` // 可利用性评分
	Impact        string      `json:"impact"`        // 潜在影响描述
	DetectedAt    time.Time   `json:"detected_at"`
	CompletedAt   *time.Time  `json:"completed_at"`
	IsActive      bool        `json:"is_active"`
}

// ChainTrigger 漏洞链触发条件（由 Manager 监控图谱变化后评估）
type ChainTrigger struct {
	TriggerID    string                 `json:"trigger_id"`
	SessionID    string                 `json:"session_id"`
	TriggerType  string                 `json:"trigger_type"`   // graph_change/vuln_found/cred_found
	Condition    map[string]interface{} `json:"condition"`      // 触发条件
	ActionPlan   []AgentTask            `json:"action_plan"`    // 触发后的执行计划
	TriggeredAt  time.Time              `json:"triggered_at"`
	Priority     TaskPriority           `json:"priority"`
}

// ReflectionEvent 反思事件（双阶段容错）
type ReflectionEvent struct {
	EventID      string                 `json:"event_id"`
	SessionID    string                 `json:"session_id"`
	Phase        string                 `json:"phase"`         // micro（微观）/ macro（宏观）
	TaskID       string                 `json:"task_id"`       // 触发反思的任务
	Reason       string                 `json:"reason"`        // 反思原因（403/timeout/waf等）
	Observations map[string]interface{} `json:"observations"`  // 观察到的情况
	Actions      []string               `json:"actions"`       // 已尝试的修正措施
	Outcome      string                 `json:"outcome"`       // success/failed/pruned
	CreatedAt    time.Time              `json:"created_at"`
}
