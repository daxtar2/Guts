// Package nuclei_agent implements the Nuclei Subagent (核心漏洞探测智能体).
// The Nuclei Subagent is responsible for:
//   - Receiving fingerprints from the Recon Subagent
//   - Dynamically selecting and scheduling Nuclei templates via MCP
//   - LLM-powered dynamic template generation and sandbox validation
//   - Parsing JSONL output and extracting credentials/tokens
//   - Feeding discovered vulnerabilities to the Memory Agent
//
// Phase 2 implementation placeholder – full implementation in a subsequent PR.
package nuclei_agent
