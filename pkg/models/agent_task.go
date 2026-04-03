package models

import "time"

// AgentRole 智能体角色类型
type AgentRole string

const (
	RoleManager    AgentRole = "manager"
	RoleMemory     AgentRole = "memory"
	RoleRecon      AgentRole = "recon"
	RoleNuclei     AgentRole = "nuclei"
	RoleExploit    AgentRole = "exploit"
	RoleAnalysis   AgentRole = "analysis"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
	TaskStatusReflecting TaskStatus = "reflecting"
)

// TaskPriority 任务优先级
type TaskPriority int

const (
	PriorityLow    TaskPriority = 1
	PriorityNormal TaskPriority = 5
	PriorityHigh   TaskPriority = 8
	PriorityCritical TaskPriority = 10
)

// AgentTask 智能体任务定义
type AgentTask struct {
	ID           string                 `json:"id"`            // 任务唯一ID
	ParentID     string                 `json:"parent_id"`     // 父任务ID（用于任务链）
	AssignedTo   AgentRole              `json:"assigned_to"`   // 分配给哪个智能体
	AssignedBy   AgentRole              `json:"assigned_by"`   // 由哪个智能体分配
	Type         string                 `json:"type"`          // 任务类型
	Target       string                 `json:"target"`        // 扫描目标
	Priority     TaskPriority           `json:"priority"`      // 优先级
	Status       TaskStatus             `json:"status"`        // 当前状态
	Payload      map[string]interface{} `json:"payload"`       // 任务参数载荷
	Result       map[string]interface{} `json:"result"`        // 任务结果
	Error        string                 `json:"error"`         // 错误信息
	RetryCount   int                    `json:"retry_count"`   // 重试次数
	MaxRetries   int                    `json:"max_retries"`   // 最大重试次数
	CreatedAt    time.Time              `json:"created_at"`    // 创建时间
	UpdatedAt    time.Time              `json:"updated_at"`    // 更新时间
	CompletedAt  *time.Time             `json:"completed_at"`  // 完成时间
	Metadata     map[string]string      `json:"metadata"`      // 元数据
}

// TaskType 已知任务类型常量
const (
	TaskTypeRecon           = "recon"
	TaskTypeFingerprint     = "fingerprint"
	TaskTypeNucleiScan      = "nuclei_scan"
	TaskTypeTemplateGen     = "template_gen"
	TaskTypeExploit         = "exploit"
	TaskTypePostExploit     = "post_exploit"
	TaskTypeAnalysis        = "analysis"
	TaskTypeMemoryStore     = "memory_store"
	TaskTypeMemoryQuery     = "memory_query"
	TaskTypeChainDetect     = "chain_detect"
)

// TaskMessage Manager 和 Subagent 之间的通信消息
type TaskMessage struct {
	MessageID   string                 `json:"message_id"`
	TaskID      string                 `json:"task_id"`
	FromAgent   AgentRole              `json:"from_agent"`
	ToAgent     AgentRole              `json:"to_agent"`
	MessageType string                 `json:"message_type"`
	Content     map[string]interface{} `json:"content"`
	Timestamp   time.Time              `json:"timestamp"`
}

// MessageType 消息类型常量
const (
	MsgTypeTaskAssign   = "task_assign"
	MsgTypeTaskUpdate   = "task_update"
	MsgTypeTaskComplete = "task_complete"
	MsgTypeTaskFail     = "task_fail"
	MsgTypeQueryRequest = "query_request"
	MsgTypeQueryResult  = "query_result"
	MsgTypeEvent        = "event"
	MsgTypeReflect      = "reflect"
)
