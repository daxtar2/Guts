package tests

import (
	"testing"
	"time"

	"github.com/daxtar2/Guts/pkg/models"
	"github.com/daxtar2/Guts/pkg/orchestration"
)

// TestGlobalStateCreation tests NewGlobalState initializes fields correctly.
func TestGlobalStateCreation(t *testing.T) {
	state := orchestration.NewGlobalState("session-001", "example.com")

	if state.SessionID != "session-001" {
		t.Errorf("expected SessionID 'session-001', got '%s'", state.SessionID)
	}
	if state.Target != "example.com" {
		t.Errorf("expected Target 'example.com', got '%s'", state.Target)
	}
	if state.Phase != orchestration.PhaseInit {
		t.Errorf("expected Phase %s, got %s", orchestration.PhaseInit, state.Phase)
	}
	if state.NextNode != orchestration.NodeIDRecon {
		t.Errorf("expected NextNode %s, got %s", orchestration.NodeIDRecon, state.NextNode)
	}
	if state.Vulnerabilities == nil {
		t.Error("Vulnerabilities slice should be initialized")
	}
	if state.DiscoveredHosts == nil {
		t.Error("DiscoveredHosts slice should be initialized")
	}
}

// TestGlobalStateAddVulnerability tests thread-safe vulnerability addition.
func TestGlobalStateAddVulnerability(t *testing.T) {
	state := orchestration.NewGlobalState("session-002", "example.com")

	vuln := models.VulnerabilityEntity{
		ID:       "vuln-001",
		Name:     "Apache RCE",
		Severity: "critical",
		Status:   models.VulnStatusPotential,
		Target:   "https://example.com/api",
		Host:     "1.2.3.4",
	}

	state.AddVulnerability(vuln)

	if state.Statistics.VulnsFound != 1 {
		t.Errorf("expected VulnsFound=1, got %d", state.Statistics.VulnsFound)
	}
	if len(state.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(state.Vulnerabilities))
	}
	if !state.GraphChanged {
		t.Error("GraphChanged should be true after adding a vulnerability")
	}
}

// TestGlobalStateAddCredential tests credential tracking.
func TestGlobalStateAddCredential(t *testing.T) {
	state := orchestration.NewGlobalState("session-003", "example.com")

	cred := models.CredentialEntity{
		Type:    "token",
		Value:   "csrf_abc123",
		Context: "/api/v1/config",
		Source:  "nuclei-csrf-detect",
	}

	state.AddCredential(cred)

	if state.Statistics.CredentialsFound != 1 {
		t.Errorf("expected CredentialsFound=1, got %d", state.Statistics.CredentialsFound)
	}
	if !state.GraphChanged {
		t.Error("GraphChanged should be true after adding a credential")
	}
}

// TestGlobalStateAddHost tests host discovery tracking.
func TestGlobalStateAddHost(t *testing.T) {
	state := orchestration.NewGlobalState("session-004", "example.com")

	host := models.HostEntity{
		IP:        "192.168.1.1",
		Hostname:  "internal.example.com",
		OS:        "Linux",
		Status:    "up",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	state.AddHost(host)

	if state.Statistics.HostsDiscovered != 1 {
		t.Errorf("expected HostsDiscovered=1, got %d", state.Statistics.HostsDiscovered)
	}
	if len(state.DiscoveredHosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(state.DiscoveredHosts))
	}
}

// TestGlobalStateGetHighSeverityVulns tests severity filtering.
func TestGlobalStateGetHighSeverityVulns(t *testing.T) {
	state := orchestration.NewGlobalState("session-005", "example.com")

	vulns := []models.VulnerabilityEntity{
		{ID: "v1", Severity: "critical", Status: models.VulnStatusPotential},
		{ID: "v2", Severity: "high", Status: models.VulnStatusPotential},
		{ID: "v3", Severity: "medium", Status: models.VulnStatusPotential},
		{ID: "v4", Severity: "low", Status: models.VulnStatusPotential},
		{ID: "v5", Severity: "info", Status: models.VulnStatusPotential},
	}

	for _, v := range vulns {
		state.AddVulnerability(v)
	}

	highSevere := state.GetHighSeverityVulns()
	if len(highSevere) != 2 {
		t.Errorf("expected 2 high/critical vulns, got %d", len(highSevere))
	}
}

// TestGlobalStateSetPhase tests phase transitions.
func TestGlobalStateSetPhase(t *testing.T) {
	state := orchestration.NewGlobalState("session-006", "example.com")

	state.SetPhase(orchestration.PhaseScan)
	if state.Phase != orchestration.PhaseScan {
		t.Errorf("expected Phase %s, got %s", orchestration.PhaseScan, state.Phase)
	}
}

// TestGlobalStateSetNextNode tests routing node setting.
func TestGlobalStateSetNextNode(t *testing.T) {
	state := orchestration.NewGlobalState("session-007", "example.com")

	state.SetNextNode(orchestration.NodeIDNuclei)
	if state.NextNode != orchestration.NodeIDNuclei {
		t.Errorf("expected NextNode %s, got %s", orchestration.NodeIDNuclei, state.NextNode)
	}
}

// TestAgentTaskModel tests the AgentTask model fields.
func TestAgentTaskModel(t *testing.T) {
	task := models.AgentTask{
		ID:         "task-001",
		AssignedTo: models.RoleNuclei,
		AssignedBy: models.RoleManager,
		Type:       models.TaskTypeNucleiScan,
		Target:     "https://example.com",
		Priority:   models.PriorityHigh,
		Status:     models.TaskStatusPending,
		Payload: map[string]interface{}{
			"tags":     "cve,apache",
			"severity": "critical,high",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if task.AssignedTo != models.RoleNuclei {
		t.Errorf("expected RoleNuclei, got %s", task.AssignedTo)
	}
	if task.Priority != models.PriorityHigh {
		t.Errorf("expected PriorityHigh (%d), got %d", models.PriorityHigh, task.Priority)
	}
	if task.Status != models.TaskStatusPending {
		t.Errorf("expected TaskStatusPending, got %s", task.Status)
	}
}

// TestVulnerabilityChainModel tests the VulnerabilityChain model.
func TestVulnerabilityChainModel(t *testing.T) {
	now := time.Now()
	chain := models.VulnerabilityChain{
		ID:          "chain-001",
		SessionID:   "session-001",
		Type:        models.ChainTypeInfoLeak,
		Name:        "CSRF Token Leak → Admin Takeover",
		RiskScore:   9.5,
		DetectedAt:  now,
		IsActive:    true,
		Nodes: []models.ChainNode{
			{
				NodeID:  "n1",
				VulnID:  "vuln-csrf",
				Action:  "extract_csrf_token",
				Status:  models.ChainNodeCompleted,
			},
			{
				NodeID:  "n2",
				VulnID:  "vuln-auth-bypass",
				Action:  "exploit_admin_panel",
				Status:  models.ChainNodePending,
			},
		},
	}

	if len(chain.Nodes) != 2 {
		t.Errorf("expected 2 chain nodes, got %d", len(chain.Nodes))
	}
	if chain.Type != models.ChainTypeInfoLeak {
		t.Errorf("expected ChainTypeInfoLeak, got %s", chain.Type)
	}
}
