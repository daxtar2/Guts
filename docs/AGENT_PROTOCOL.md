# Agent Communication Protocol

## Overview

All inter-agent communication follows a structured JSON RPC message format defined in
`pkg/models/agent_task.go`. The Manager Agent is the central hub — subagents never
communicate directly with each other.

## Message Structure

```json
{
  "message_id": "msg_20260403120000.000000001",
  "task_id": "task_abc123",
  "from_agent": "manager",
  "to_agent": "nuclei",
  "message_type": "task_assign",
  "content": {
    "type": "nuclei_scan",
    "target": "https://example.com",
    "tags": "cve,apache",
    "severity": "critical,high",
    "priority": 8
  },
  "timestamp": "2026-04-03T12:00:00Z"
}
```

## Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `task_assign` | Manager → Subagent | Assign a new task |
| `task_update` | Subagent → Manager | Progress update |
| `task_complete` | Subagent → Manager | Task completed with results |
| `task_fail` | Subagent → Manager | Task failed with error details |
| `query_request` | Manager → Memory | Query the knowledge graph |
| `query_result` | Memory → Manager | Query results |
| `event` | Any → EventBus | Broadcast a system event |
| `reflect` | Manager → Any | Trigger reflection/retry |

## Task Types

| Task Type | Assigned To | Description |
|-----------|-------------|-------------|
| `recon` | Recon | Asset discovery |
| `fingerprint` | Recon | Technology fingerprinting |
| `nuclei_scan` | Nuclei | Targeted vulnerability scan |
| `template_gen` | Nuclei | LLM-powered template generation |
| `exploit` | Exploit | Vulnerability exploitation |
| `post_exploit` | Exploit | Post-exploitation actions |
| `analysis` | Analysis | Result analysis and report generation |
| `memory_store` | Memory | Store entities to graph |
| `memory_query` | Memory | Query graph for context |
| `chain_detect` | Manager | Vulnerability chain detection |

## Priority Levels

| Level | Value | Use Case |
|-------|-------|----------|
| `PriorityLow` | 1 | Background recon tasks |
| `PriorityNormal` | 5 | Standard scans |
| `PriorityHigh` | 8 | High-severity vulnerability follow-up |
| `PriorityCritical` | 10 | Credential found, immediate exploit attempt |

## Event Bus

The Event Bus (`pkg/orchestration/event_bus.go`) enables reactive, event-driven behavior:

### Key Events

| Event | Trigger | Handler |
|-------|---------|---------|
| `vuln_found` | Nuclei finds a vulnerability | Manager evaluates chain potential |
| `cred_found` | Nuclei extracts a credential | Manager interrupts low-priority tasks, starts Exploit |
| `graph_changed` | Memory writes new data | Manager re-evaluates strategy |
| `chain_detected` | Manager detects a chain | Manager prioritizes exploit path |
| `reflect_triggered` | Repeated failures | Manager adjusts parameters |
| `phase_transition` | Phase changes | All agents acknowledge |

### Event Flow Example

```
Nuclei extracts CSRF token
  → Publishes "cred_found" event to EventBus
  → EventBus dispatches to Manager's handler
  → Manager creates high-priority "exploit" task
  → Manager assigns task to Exploit Subagent
  → Exploit publishes "task_complete" event
  → Manager updates GlobalState
```

## MCP Protocol

Subagents interact with underlying tools (Nuclei, etc.) exclusively through the
Model Context Protocol (MCP) via `pkg/mcp/`.

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_templates` | List Nuclei templates filtered by tags/severity |
| `run_scan` | Execute a Nuclei scan and return parsed JSONL results |
| `validate_template` | Validate a generated template with `nuclei -validate` |

### MCP Tool Call Example

```json
{
  "tool": "run_scan",
  "input": {
    "target": "https://example.com",
    "tags": "cve,struts",
    "severity": "critical,high",
    "rate_limit": 30
  }
}
```
