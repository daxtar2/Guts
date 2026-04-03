# Usage Examples

## Basic Usage (Phase 1 - Coming Soon)

The full agent system will be available from `cmd/main.go` with an `--agent-mode` flag.

```bash
# Start in multi-agent mode
./guts --agent-mode --target example.com

# Use a custom agent config
./guts --agent-mode --agent-config ./config/agent_config.yaml --target example.com

# Start with exploit subagent enabled (requires explicit authorization)
./guts --agent-mode --enable-exploit --target example.com
```

## Programmatic Usage (Phase 1 API - Coming Soon)

```go
package main

import (
    "context"
    "fmt"

    "github.com/daxtar2/Guts/pkg/orchestration"
    "github.com/google/uuid"
)

func main() {
    ctx := context.Background()

    // Create session state
    sessionID := uuid.New().String()
    state := orchestration.NewGlobalState(sessionID, "example.com")

    // Build the execution graph (Phase 1 will provide concrete agent implementations)
    graph := orchestration.BuildDefaultGraph(
        managerNode,   // Phase 1: pkg/agent/manager
        memoryNode,    // Phase 1: pkg/agent/memory
        reconNode,     // Phase 2: pkg/agent/recon
        nucleiNode,    // Phase 2: pkg/agent/nuclei_agent
        exploitNode,   // Phase 2: pkg/agent/exploit
        analysisNode,  // Phase 2: pkg/agent/analysis
        reflectNode,   // Phase 1: built-in reflection handler
    )

    finalState, err := graph.Execute(ctx, state)
    if err != nil {
        fmt.Printf("Execution error: %v\n", err)
        return
    }

    fmt.Printf("Vulnerabilities found: %d\n", finalState.Statistics.VulnsFound)
    fmt.Printf("Credentials found: %d\n", finalState.Statistics.CredentialsFound)
    fmt.Printf("Attack chains detected: %d\n", len(finalState.DetectedChains))
}
```

## Neo4j Graph Queries

After a scan session, query the knowledge graph directly:

```cypher
// List all discovered hosts with their technology stacks
MATCH (h:Host)-[:RUNS]->(t:Technology)
RETURN h.ip, h.hostname, collect(t.name + ':' + t.version) AS tech_stack

// Find attack chains: technology → vulnerability → credential
MATCH (h:Host)-[:RUNS]->(t:Technology)
MATCH (v:Vulnerability)-[:AFFECTS]->(h)
MATCH (h)-[:EXPOSES_TOKEN]->(c:Credential)
WHERE v.severity IN ["critical", "high"]
RETURN h.ip, t.name, v.name, v.severity, c.type
ORDER BY v.severity

// Count vulnerabilities by severity
MATCH (v:Vulnerability)
RETURN v.severity, count(v) AS count
ORDER BY count DESC
```

## Dynamic Template Generation (Phase 2)

The LLM-powered template generator can create custom Nuclei templates:

```go
import (
    "github.com/daxtar2/Guts/pkg/llm"
)

gen := llm.NewTemplateGenerator(
    llm.NewOpenAIClient(llm.OpenAIConfig{
        APIKey: os.Getenv("OPENAI_API_KEY"),
        Model:  "gpt-4o",
    }),
    llm.TemplateGeneratorConfig{
        SandboxEnabled: true,
        MaxIterations:  3,
    },
)

tmpl, err := gen.GenerateTemplate(ctx, map[string]string{
    "target_info":     "Apache Struts 2.3.x",
    "vuln_type":       "remote-code-execution",
    "swagger_snippet": "/api/execute POST body: {cmd: string}",
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(tmpl.RawTemplate)
```

## MCP Tool Invocation

```go
import (
    "github.com/daxtar2/Guts/pkg/mcp"
)

server := mcp.NewNucleiMCPServer(mcp.NucleiMCPConfig{
    NucleiBinaryPath: "nuclei",
    TemplatesPath:    "./templates",
    RateLimit:        30,
    BulkSize:         10,
})

// List templates matching Apache + CVE tags
output, err := server.GetRegistry().Execute(ctx, "list_templates", mcp.ToolInput{
    "tags":     "cve,apache",
    "severity": "critical,high",
})

// Run a targeted scan
output, err = server.GetRegistry().Execute(ctx, "run_scan", mcp.ToolInput{
    "target":   "https://example.com",
    "tags":     "struts,cve-2017",
    "severity": "critical",
})
```
