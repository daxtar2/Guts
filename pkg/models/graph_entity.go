package models

import "time"

// NodeLabel Neo4j 节点标签类型
type NodeLabel string

const (
	NodeLabelHost        NodeLabel = "Host"
	NodeLabelService     NodeLabel = "Service"
	NodeLabelPort        NodeLabel = "Port"
	NodeLabelDomain      NodeLabel = "Domain"
	NodeLabelTechnology  NodeLabel = "Technology"
	NodeLabelVulnerability NodeLabel = "Vulnerability"
	NodeLabelCredential  NodeLabel = "Credential"
	NodeLabelToken       NodeLabel = "Token"
	NodeLabelEndpoint    NodeLabel = "Endpoint"
)

// RelationshipType Neo4j 关系类型
type RelationshipType string

const (
	RelRuns          RelationshipType = "RUNS"
	RelExposes       RelationshipType = "EXPOSES"
	RelAffects       RelationshipType = "AFFECTS"
	RelContains      RelationshipType = "CONTAINS"
	RelLinksTo       RelationshipType = "LINKS_TO"
	RelAuthenticate  RelationshipType = "AUTHENTICATES_WITH"
	RelExposesToken  RelationshipType = "EXPOSES_TOKEN"
	RelHasEndpoint   RelationshipType = "HAS_ENDPOINT"
	RelPartOf        RelationshipType = "PART_OF"
	RelDiscoveredBy  RelationshipType = "DISCOVERED_BY"
)

// GraphNode 图谱节点基础结构
type GraphNode struct {
	ID         string            `json:"id"`
	Labels     []NodeLabel       `json:"labels"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// GraphRelationship 图谱关系
type GraphRelationship struct {
	ID         string                 `json:"id"`
	Type       RelationshipType       `json:"type"`
	StartNode  string                 `json:"start_node"`
	EndNode    string                 `json:"end_node"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
}

// HostEntity 主机实体
type HostEntity struct {
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Status      string    `json:"status"` // up/down/unknown
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
}

// ServiceEntity 服务实体
type ServiceEntity struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Banner     string   `json:"banner"`
	Protocol   string   `json:"protocol"` // http/https/ftp/ssh etc.
	Port       int      `json:"port"`
	State      string   `json:"state"` // open/closed/filtered
	Tags       []string `json:"tags"`
}

// TechnologyEntity 技术栈实体（来自 Wappalyzer 等指纹识别）
type TechnologyEntity struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Category   string   `json:"category"` // CMS/Framework/Server/Language etc.
	Confidence int      `json:"confidence"` // 0-100 识别置信度
	Tags       []string `json:"tags"`
}

// CredentialEntity 凭据实体
type CredentialEntity struct {
	Type     string `json:"type"`     // username/password/token/apikey/cookie
	Value    string `json:"value"`    // 凭据值（敏感数据）
	Context  string `json:"context"`  // 发现位置/上下文
	Source   string `json:"source"`   // 来源（nuclei_template_id等）
	Verified bool   `json:"verified"` // 是否已验证有效
}

// GraphQueryRequest 图谱查询请求
type GraphQueryRequest struct {
	QueryType  string                 `json:"query_type"`
	Parameters map[string]interface{} `json:"parameters"`
	CypherQuery string               `json:"cypher_query,omitempty"`
}

// GraphQueryResult 图谱查询结果
type GraphQueryResult struct {
	Nodes         []GraphNode         `json:"nodes"`
	Relationships []GraphRelationship `json:"relationships"`
	Records       []map[string]interface{} `json:"records"`
	Count         int                 `json:"count"`
}
