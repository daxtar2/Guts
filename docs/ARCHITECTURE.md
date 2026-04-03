# Guts Multi-Agent Penetration Testing Intelligence System

## Architecture Overview

Guts has evolved from a single Nuclei-based passive scanner into a layered multi-agent
penetration testing intelligence system. The system is built on a LangGraph-inspired state
machine orchestration framework with four distinct layers.

```
┌──────────────────────────────────────────────────────────┐
│  Decision Orchestration Layer: Manager Agent             │
│  - Task decomposition, state management, global dispatch │
└──────────────┬───────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────┐
│  Context Persistence Layer: Memory Agent + Neo4j         │
│  - Entity relationship extraction, knowledge graph       │
│  - Context retrieval, graph change event broadcasting    │
└──────────────┬───────────────────────────────────────────┘
               │
    ┌──────────┴──────┬──────────────┬────────────────┐
    │                 │              │                │
┌───▼────────┐ ┌──────▼──────┐ ┌────▼───────┐ ┌─────▼─────┐
│   Recon    │ │   Nuclei    │ │  Exploit   │ │ Analysis  │
│  Subagent  │ │  Subagent   │ │  Subagent  │ │ Subagent  │
│(Asset Ing.)│ │(Det. Scan)  │ │(Deep Expl.)│ │(Synthesis)│
└────────────┘ └─────────────┘ └────────────┘ └───────────┘
```

## Agent Role Definitions

| Agent | Layer | Responsibilities | Permission Boundary | Protocol |
|-------|-------|-----------------|---------------------|----------|
| **Manager** | Decision | Task decomposition, scheduling, global coordination | Issues instructions only, no direct tool execution | JSON RPC |
| **Memory** | Persistence | Graph maintenance, entity relationship management, retrieval | Listens to data bus, provides query interface | Cypher/Events |
| **Recon** | Ingestion | Asset discovery, technology fingerprinting, passive/active mapping | Wappalyzer, DNS, HTTP fingerprinting | MCP |
| **Nuclei** | Scanning | Targeted vulnerability detection, dynamic template generation | MCP interface to Nuclei engine only | MCP/JSONL |
| **Exploit** | Exploitation | Vulnerability verification, post-exploitation, credential extraction | Graph-driven precise attack (requires authorization) | MCP |
| **Analysis** | Synthesis | Result correlation, risk scoring, report generation | Read-only access to all agent outputs | Internal |

## Data Flow

```
User Input (example.com)
  ↓
[Manager] Strategy planning → "Recon → Fingerprint → Targeted Scan → Verify → Chain Build"
  ↓
[Recon] Asset discovery → {domains, ports, tech_stack}
  ↓
[Memory] Graph ingestion → Neo4j: Host-RUNS->Technology-EXPOSES->Port
  ↓
[Manager] Graph query → retrieves technology stack labels
  ↓
[Nuclei] Targeted scan → {raw_vulns, extracted_creds}
  ↓
[Memory] Inject relationships → Neo4j: Vuln-AFFECTS->Host, Credential-EXPOSES_TOKEN->Host
  ↓
[Manager] Detects deep exploitability → triggers reflection mechanism
  ↓
[Exploit] Deep exploitation → {privilege_escalation, lateral_movement}
  ↓
[Analysis] Chain synthesis → {risk_report, remediation}
  ↓
Final Report
```

## LangGraph State Machine

The orchestration engine is implemented in `pkg/orchestration/langgraph.go`. It uses a
directed graph where:

- **Nodes** are agent execution functions
- **Edges** define valid transitions between agents
- **Conditional edges** enable the Manager to dynamically route execution based on
  the current global state
- **The GlobalState** (`pkg/orchestration/state_machine.go`) is the shared memory passed
  between nodes on each execution step

### Phase Lifecycle

```
PhaseInit → PhaseRecon → PhaseFingerprint → PhaseScan → PhaseExploit → PhaseAnalysis → PhaseComplete
                                                                ↑              ↓
                                                          PhaseReflect ←── (on error)
```

## Dual-Phase Reflection Mechanism

### Micro-level Correction
Triggered when a specific scan path encounters repeated 403/timeout responses:
1. WAF fingerprint analysis
2. Automatic proxy switching
3. User-Agent rotation
4. Rate limit adjustment

### Macro-level Pruning
Triggered when micro-level corrections fail `reflection_threshold` times:
1. Mark attack path as infeasible in the knowledge graph
2. Signal Manager to re-plan with alternative paths
3. Prevents infinite loop exhaustion of compute/cost

## Package Structure

```
pkg/
├── agent/
│   ├── manager/        # Manager Agent (Phase 1)
│   ├── memory/         # Memory Agent + Neo4j (Phase 1)
│   ├── recon/          # Recon Subagent (Phase 2)
│   ├── nuclei_agent/   # Nuclei Subagent + MCP (Phase 2)
│   ├── exploit/        # Exploit Subagent (Phase 2)
│   └── analysis/       # Analysis Subagent (Phase 2)
├── orchestration/
│   ├── langgraph.go    # State machine execution engine
│   ├── state_machine.go # GlobalState definition
│   └── event_bus.go    # Event-driven bus
├── models/
│   ├── agent_task.go   # Task and message models
│   ├── graph_entity.go # Neo4j entity models
│   ├── vulnerability.go # Vulnerability and scan models
│   └── chain_detection.go # Vulnerability chain models
├── storage/
│   └── neo4j_client.go # Graph database client
├── llm/
│   ├── openai_client.go       # LLM integration
│   └── template_generator.go  # Dynamic template generation
└── mcp/
    ├── nuclei_mcp.go    # Nuclei MCP Server
    └── tool_registry.go # MCP tool registry
```

## Implementation Roadmap

- **Phase 0 (Current)**: Architecture foundation — data models, state machine, Neo4j schema
- **Phase 1 (Next PR)**: Manager Agent + Memory Agent + LangGraph engine + event bus
- **Phase 2 (Subsequent)**: All subagents (Recon, Nuclei, Exploit, Analysis)
- **Phase 3 (Future)**: Automatic chain building, LLM template generation, observability
