// Package storage 提供图数据库和持久化存储的客户端实现。
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"go.uber.org/zap"
)

// Neo4jConfig Neo4j 连接配置
type Neo4jConfig struct {
	URI      string `mapstructure:"uri"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
}

// Neo4jClient Neo4j 图数据库客户端
type Neo4jClient struct {
	driver   neo4j.DriverWithContext
	config   Neo4jConfig
	database string
}

// NewNeo4jClient 创建新的 Neo4j 客户端
func NewNeo4jClient(cfg Neo4jConfig) (*Neo4jClient, error) {
	database := cfg.Database
	if database == "" {
		database = "neo4j"
	}

	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("创建 Neo4j 驱动失败: %w", err)
	}

	client := &Neo4jClient{
		driver:   driver,
		config:   cfg,
		database: database,
	}

	// 验证连接
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("Neo4j 连接验证失败: %w", err)
	}

	logger.Info("Neo4j 连接成功", zap.String("uri", cfg.URI))
	return client, nil
}

// Close 关闭连接
func (c *Neo4jClient) Close(ctx context.Context) error {
	return c.driver.Close(ctx)
}

// InitSchema 初始化 Neo4j Schema（索引和约束）
func (c *Neo4jClient) InitSchema(ctx context.Context) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	constraints := []string{
		// 主机节点唯一约束
		`CREATE CONSTRAINT host_ip_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE`,
		// 域名节点唯一约束
		`CREATE CONSTRAINT domain_name_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE`,
		// 漏洞节点唯一约束
		`CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE`,
		// 服务节点索引
		`CREATE INDEX service_name_idx IF NOT EXISTS FOR (s:Service) ON (s.name, s.version)`,
		// 技术栈节点索引
		`CREATE INDEX tech_name_idx IF NOT EXISTS FOR (t:Technology) ON (t.name)`,
	}

	for _, cypher := range constraints {
		if _, err := session.Run(ctx, cypher, nil); err != nil {
			// 忽略约束已存在的错误，记录其他错误
			logger.Warn("Schema 初始化语句执行失败（可能已存在）",
				zap.String("cypher", cypher),
				zap.Error(err))
		}
	}

	return nil
}

// UpsertHost 写入或更新主机节点
func (c *Neo4jClient) UpsertHost(ctx context.Context, host models.HostEntity) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MERGE (h:Host {ip: $ip})
		SET h.hostname = $hostname,
		    h.os = $os,
		    h.status = $status,
		    h.tags = $tags,
		    h.last_seen = $last_seen,
		    h.first_seen = COALESCE(h.first_seen, $first_seen)
		RETURN h`

	params := map[string]interface{}{
		"ip":         host.IP,
		"hostname":   host.Hostname,
		"os":         host.OS,
		"status":     host.Status,
		"tags":       host.Tags,
		"last_seen":  host.LastSeen.Unix(),
		"first_seen": host.FirstSeen.Unix(),
	}

	_, err := session.Run(ctx, cypher, params)
	return err
}

// UpsertVulnerability 写入或更新漏洞节点，并建立与主机的关系
func (c *Neo4jClient) UpsertVulnerability(ctx context.Context, vuln models.VulnerabilityEntity) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MERGE (v:Vulnerability {id: $id})
		SET v.template_id = $template_id,
		    v.name = $name,
		    v.severity = $severity,
		    v.status = $status,
		    v.target = $target,
		    v.matched_at = $matched_at,
		    v.description = $description,
		    v.tags = $tags,
		    v.discovered_at = $discovered_at
		WITH v
		MATCH (h:Host {ip: $host})
		MERGE (v)-[:AFFECTS]->(h)
		RETURN v`

	params := map[string]interface{}{
		"id":           vuln.ID,
		"template_id":  vuln.TemplateID,
		"name":         vuln.Name,
		"severity":     vuln.Severity,
		"status":       string(vuln.Status),
		"target":       vuln.Target,
		"host":         vuln.Host,
		"matched_at":   vuln.MatchedAt,
		"description":  vuln.Description,
		"tags":         vuln.Tags,
		"discovered_at": vuln.DiscoveredAt.Unix(),
	}

	_, err := session.Run(ctx, cypher, params)
	return err
}

// UpsertTechnology 写入或更新技术栈节点，并建立与主机的关系
func (c *Neo4jClient) UpsertTechnology(ctx context.Context, host string, tech models.TechnologyEntity) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MERGE (t:Technology {name: $name, version: $version})
		SET t.category = $category,
		    t.confidence = $confidence
		WITH t
		MATCH (h:Host {ip: $host})
		MERGE (h)-[:RUNS]->(t)
		RETURN t`

	params := map[string]interface{}{
		"name":       tech.Name,
		"version":    tech.Version,
		"category":   tech.Category,
		"confidence": tech.Confidence,
		"host":       host,
	}

	_, err := session.Run(ctx, cypher, params)
	return err
}

// StoreCredential 存储凭据节点并关联到目标主机
func (c *Neo4jClient) StoreCredential(ctx context.Context, hostIP string, cred models.CredentialEntity) error {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MERGE (c:Credential {type: $type, context: $context})
		SET c.value = $value,
		    c.source = $source,
		    c.verified = $verified
		WITH c
		MATCH (h:Host {ip: $host_ip})
		MERGE (h)-[:EXPOSES_TOKEN]->(c)
		RETURN c`

	params := map[string]interface{}{
		"type":     cred.Type,
		"context":  cred.Context,
		"value":    cred.Value,
		"source":   cred.Source,
		"verified": cred.Verified,
		"host_ip":  hostIP,
	}

	_, err := session.Run(ctx, cypher, params)
	return err
}

// QueryTechStack 查询目标主机的技术栈（用于 Manager 制定扫描策略）
func (c *Neo4jClient) QueryTechStack(ctx context.Context, hostIP string) ([]models.TechnologyEntity, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MATCH (h:Host {ip: $host_ip})-[:RUNS]->(t:Technology)
		RETURN t.name AS name, t.version AS version, t.category AS category, t.confidence AS confidence`

	result, err := session.Run(ctx, cypher, map[string]interface{}{"host_ip": hostIP})
	if err != nil {
		return nil, err
	}

	var techs []models.TechnologyEntity
	for result.Next(ctx) {
		record := result.Record()
		name, _ := record.Get("name")
		version, _ := record.Get("version")
		category, _ := record.Get("category")
		confidence, _ := record.Get("confidence")

		tech := models.TechnologyEntity{
			Name:     fmt.Sprintf("%v", name),
			Version:  fmt.Sprintf("%v", version),
			Category: fmt.Sprintf("%v", category),
		}
		if conf, ok := confidence.(int64); ok {
			tech.Confidence = int(conf)
		}
		techs = append(techs, tech)
	}

	return techs, result.Err()
}

// QueryVulnerabilitiesByHost 查询主机关联的所有漏洞
func (c *Neo4jClient) QueryVulnerabilitiesByHost(ctx context.Context, hostIP string) ([]models.VulnerabilityEntity, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	cypher := `
		MATCH (v:Vulnerability)-[:AFFECTS]->(h:Host {ip: $host_ip})
		RETURN v.id AS id, v.name AS name, v.severity AS severity, 
		       v.template_id AS template_id, v.status AS status,
		       v.target AS target, v.matched_at AS matched_at`

	result, err := session.Run(ctx, cypher, map[string]interface{}{"host_ip": hostIP})
	if err != nil {
		return nil, err
	}

	var vulns []models.VulnerabilityEntity
	for result.Next(ctx) {
		record := result.Record()
		id, _ := record.Get("id")
		name, _ := record.Get("name")
		severity, _ := record.Get("severity")
		templateID, _ := record.Get("template_id")
		status, _ := record.Get("status")
		target, _ := record.Get("target")
		matchedAt, _ := record.Get("matched_at")

		vulns = append(vulns, models.VulnerabilityEntity{
			ID:         fmt.Sprintf("%v", id),
			Name:       fmt.Sprintf("%v", name),
			Severity:   fmt.Sprintf("%v", severity),
			TemplateID: fmt.Sprintf("%v", templateID),
			Status:     models.VulnerabilityStatus(fmt.Sprintf("%v", status)),
			Target:     fmt.Sprintf("%v", target),
			MatchedAt:  fmt.Sprintf("%v", matchedAt),
		})
	}

	return vulns, result.Err()
}

// ExecuteCypher 执行自定义 Cypher 查询（供 Memory Agent 使用）
func (c *Neo4jClient) ExecuteCypher(ctx context.Context, cypher string, params map[string]interface{}) ([]map[string]interface{}, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: c.database})
	defer session.Close(ctx)

	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	var records []map[string]interface{}
	for result.Next(ctx) {
		record := result.Record()
		row := make(map[string]interface{})
		for _, key := range record.Keys {
			val, _ := record.Get(key)
			row[key] = val
		}
		records = append(records, row)
	}

	return records, result.Err()
}
