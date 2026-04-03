package orchestration

import (
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/models"
)

// ExecutionPhase 渗透测试执行阶段
type ExecutionPhase string

const (
	PhaseInit        ExecutionPhase = "init"
	PhaseRecon       ExecutionPhase = "recon"
	PhaseFingerprint ExecutionPhase = "fingerprint"
	PhaseScan        ExecutionPhase = "scan"
	PhaseExploit     ExecutionPhase = "exploit"
	PhaseAnalysis    ExecutionPhase = "analysis"
	PhaseComplete    ExecutionPhase = "complete"
	PhaseFailed      ExecutionPhase = "failed"
)

// GlobalState LangGraph 全局共享状态，所有节点读写此结构
type GlobalState struct {
	mu sync.RWMutex

	// 会话元数据
	SessionID   string         `json:"session_id"`
	Target      string         `json:"target"`       // 顶级目标
	Phase       ExecutionPhase `json:"phase"`        // 当前阶段
	NextNode    NodeID         `json:"next_node"`    // 下一个执行节点（条件路由使用）
	LastError   string         `json:"last_error"`   // 最近一次错误
	StepCount   int            `json:"step_count"`   // 执行步数
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`

	// 任务队列
	PendingTasks   []models.AgentTask `json:"pending_tasks"`
	CompletedTasks []models.AgentTask `json:"completed_tasks"`
	FailedTasks    []models.AgentTask `json:"failed_tasks"`

	// 侦察结果
	DiscoveredHosts    []models.HostEntity       `json:"discovered_hosts"`
	DiscoveredServices []models.ServiceEntity    `json:"discovered_services"`
	TechStack          []models.TechnologyEntity `json:"tech_stack"`

	// 漏洞发现
	Vulnerabilities []models.VulnerabilityEntity `json:"vulnerabilities"`
	ExploitResults  []models.ExploitResult       `json:"exploit_results"`

	// 凭据与令牌
	ExtractedCredentials []models.CredentialEntity `json:"extracted_credentials"`

	// 漏洞链
	DetectedChains []models.VulnerabilityChain `json:"detected_chains"`

	// 反思记录
	ReflectionHistory []models.ReflectionEvent `json:"reflection_history"`

	// 图谱状态标记（Manager 使用）
	GraphChanged bool   `json:"graph_changed"` // 图谱是否有新变化
	GraphSummary string `json:"graph_summary"` // 图谱摘要（供 LLM 决策使用）

	// 扫描统计
	Statistics models.ScanStatistics `json:"statistics"`
}

// NewGlobalState 创建新的全局状态
func NewGlobalState(sessionID, target string) *GlobalState {
	now := time.Now()
	return &GlobalState{
		SessionID:            sessionID,
		Target:               target,
		Phase:                PhaseInit,
		NextNode:             NodeIDRecon,
		CreatedAt:            now,
		UpdatedAt:            now,
		PendingTasks:         []models.AgentTask{},
		CompletedTasks:       []models.AgentTask{},
		FailedTasks:          []models.AgentTask{},
		DiscoveredHosts:      []models.HostEntity{},
		DiscoveredServices:   []models.ServiceEntity{},
		TechStack:            []models.TechnologyEntity{},
		Vulnerabilities:      []models.VulnerabilityEntity{},
		ExploitResults:       []models.ExploitResult{},
		ExtractedCredentials: []models.CredentialEntity{},
		DetectedChains:       []models.VulnerabilityChain{},
		ReflectionHistory:    []models.ReflectionEvent{},
	}
}

// SetPhase 线程安全地设置执行阶段
func (s *GlobalState) SetPhase(phase ExecutionPhase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Phase = phase
	s.UpdatedAt = time.Now()
}

// SetNextNode 线程安全地设置下一个节点
func (s *GlobalState) SetNextNode(node NodeID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NextNode = node
	s.UpdatedAt = time.Now()
}

// AddVulnerability 线程安全地添加漏洞
func (s *GlobalState) AddVulnerability(vuln models.VulnerabilityEntity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Vulnerabilities = append(s.Vulnerabilities, vuln)
	s.Statistics.VulnsFound++
	s.GraphChanged = true
	s.UpdatedAt = time.Now()
}

// AddCredential 线程安全地添加凭据
func (s *GlobalState) AddCredential(cred models.CredentialEntity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExtractedCredentials = append(s.ExtractedCredentials, cred)
	s.Statistics.CredentialsFound++
	s.GraphChanged = true
	s.UpdatedAt = time.Now()
}

// AddHost 线程安全地添加发现的主机
func (s *GlobalState) AddHost(host models.HostEntity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DiscoveredHosts = append(s.DiscoveredHosts, host)
	s.Statistics.HostsDiscovered++
	s.UpdatedAt = time.Now()
}

// AddChain 线程安全地添加漏洞链
func (s *GlobalState) AddChain(chain models.VulnerabilityChain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DetectedChains = append(s.DetectedChains, chain)
	s.UpdatedAt = time.Now()
}

// AddReflection 记录反思事件
func (s *GlobalState) AddReflection(event models.ReflectionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ReflectionHistory = append(s.ReflectionHistory, event)
	s.UpdatedAt = time.Now()
}

// GetHighSeverityVulns 获取高危及以上漏洞列表
func (s *GlobalState) GetHighSeverityVulns() []models.VulnerabilityEntity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []models.VulnerabilityEntity
	for _, v := range s.Vulnerabilities {
		if v.Severity == "critical" || v.Severity == "high" {
			result = append(result, v)
		}
	}
	return result
}

// HasExploitableVulns 检查是否有可利用的漏洞（含凭据提取）
func (s *GlobalState) HasExploitableVulns() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.ExtractedCredentials) > 0 ||
		s.Statistics.VulnsFound > 0 && (s.Statistics.CredentialsFound > 0)
}
