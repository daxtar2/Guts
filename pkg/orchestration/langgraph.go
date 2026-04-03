// Package orchestration 实现基于 LangGraph 状态图的多智能体编排框架。
// 本包定义了全局状态机、节点转换逻辑和执行引擎骨架。
package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// NodeID 状态机节点ID
type NodeID string

const (
	NodeIDStart      NodeID = "start"
	NodeIDManager    NodeID = "manager"
	NodeIDMemory     NodeID = "memory"
	NodeIDRecon      NodeID = "recon"
	NodeIDNuclei     NodeID = "nuclei"
	NodeIDExploit    NodeID = "exploit"
	NodeIDAnalysis   NodeID = "analysis"
	NodeIDReflect    NodeID = "reflect"
	NodeIDEnd        NodeID = "end"
)

// NodeFunc 节点执行函数签名
type NodeFunc func(ctx context.Context, state *GlobalState) (*GlobalState, error)

// EdgeCondition 条件边函数签名：返回下一个节点ID
type EdgeCondition func(state *GlobalState) NodeID

// GraphNode 状态图节点
type GraphNode struct {
	ID       NodeID
	Name     string
	Execute  NodeFunc
	IsEntry  bool
	IsEnd    bool
}

// GraphEdge 状态图边（转换规则）
type GraphEdge struct {
	From      NodeID
	To        NodeID
	Condition EdgeCondition // nil 表示无条件转换
}

// LangGraph 状态图编排引擎
type LangGraph struct {
	mu          sync.RWMutex
	nodes       map[NodeID]*GraphNode
	edges       []GraphEdge
	entryNode   NodeID
	maxSteps    int
	stepTimeout time.Duration
}

// NewLangGraph 创建新的状态图编排引擎
func NewLangGraph() *LangGraph {
	return &LangGraph{
		nodes:       make(map[NodeID]*GraphNode),
		edges:       []GraphEdge{},
		maxSteps:    100,
		stepTimeout: 30 * time.Minute,
	}
}

// AddNode 添加节点到状态图
func (g *LangGraph) AddNode(node *GraphNode) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[node.ID]; exists {
		return fmt.Errorf("node %s already exists", node.ID)
	}
	g.nodes[node.ID] = node
	if node.IsEntry {
		g.entryNode = node.ID
	}
	return nil
}

// AddEdge 添加有向边
func (g *LangGraph) AddEdge(from, to NodeID, condition EdgeCondition) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.edges = append(g.edges, GraphEdge{
		From:      from,
		To:        to,
		Condition: condition,
	})
}

// AddConditionalEdge 添加条件边（一个节点根据条件分发到不同的后继节点）
func (g *LangGraph) AddConditionalEdge(from NodeID, condition EdgeCondition) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.edges = append(g.edges, GraphEdge{
		From:      from,
		To:        "",
		Condition: condition,
	})
}

// Execute 执行状态图
func (g *LangGraph) Execute(ctx context.Context, initialState *GlobalState) (*GlobalState, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.entryNode == "" {
		return nil, fmt.Errorf("no entry node defined")
	}

	currentNode := g.entryNode
	state := initialState
	steps := 0

	for {
		if steps >= g.maxSteps {
			return state, fmt.Errorf("max steps (%d) exceeded", g.maxSteps)
		}

		// 检查上下文
		select {
		case <-ctx.Done():
			return state, ctx.Err()
		default:
		}

		node, exists := g.nodes[currentNode]
		if !exists {
			return state, fmt.Errorf("node %s not found", currentNode)
		}

		// 如果是终止节点，停止执行
		if node.IsEnd {
			break
		}

		// 执行节点，带超时
		nodeCtx, cancel := context.WithTimeout(ctx, g.stepTimeout)
		newState, err := node.Execute(nodeCtx, state)
		cancel()
		if err != nil {
			state.LastError = err.Error()
			// 错误时尝试触发反思节点
			if currentNode != NodeIDReflect {
				currentNode = NodeIDReflect
				steps++
				continue
			}
			return state, fmt.Errorf("node %s execution failed: %w", currentNode, err)
		}
		state = newState
		steps++

		// 查找下一个节点
		nextNode := g.findNextNode(currentNode, state)
		if nextNode == "" {
			break
		}
		currentNode = nextNode
	}

	return state, nil
}

// findNextNode 根据边定义找到下一个节点
func (g *LangGraph) findNextNode(current NodeID, state *GlobalState) NodeID {
	for _, edge := range g.edges {
		if edge.From != current {
			continue
		}
		if edge.Condition == nil {
			return edge.To
		}
		// 有条件边：执行条件函数
		if edge.To == "" {
			return edge.Condition(state)
		}
		// 有具体目标的条件边
		if edge.Condition(state) == edge.To {
			return edge.To
		}
	}
	return ""
}

// BuildDefaultGraph 构建默认的渗透测试状态图
func BuildDefaultGraph(
	managerFn NodeFunc,
	memoryFn NodeFunc,
	reconFn NodeFunc,
	nucleiFn NodeFunc,
	exploitFn NodeFunc,
	analysisFn NodeFunc,
	reflectFn NodeFunc,
) *LangGraph {
	g := NewLangGraph()

	// 注册节点
	_ = g.AddNode(&GraphNode{ID: NodeIDManager, Name: "Manager Agent", Execute: managerFn, IsEntry: true})
	_ = g.AddNode(&GraphNode{ID: NodeIDMemory, Name: "Memory Agent", Execute: memoryFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDRecon, Name: "Recon Subagent", Execute: reconFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDNuclei, Name: "Nuclei Subagent", Execute: nucleiFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDExploit, Name: "Exploit Subagent", Execute: exploitFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDAnalysis, Name: "Analysis Subagent", Execute: analysisFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDReflect, Name: "Reflection Node", Execute: reflectFn})
	_ = g.AddNode(&GraphNode{ID: NodeIDEnd, Name: "End", IsEnd: true})

	// Manager → 条件分发（根据当前阶段决定下一步）
	g.AddConditionalEdge(NodeIDManager, func(state *GlobalState) NodeID {
		return state.NextNode
	})

	// Recon → Memory（存入发现的资产）
	g.AddEdge(NodeIDRecon, NodeIDMemory, nil)

	// Memory → Manager（存储完成，回报）
	g.AddEdge(NodeIDMemory, NodeIDManager, nil)

	// Nuclei → Memory（存入发现的漏洞）
	g.AddEdge(NodeIDNuclei, NodeIDMemory, nil)

	// Exploit → Memory（存入利用结果）
	g.AddEdge(NodeIDExploit, NodeIDMemory, nil)

	// Analysis → End
	g.AddEdge(NodeIDAnalysis, NodeIDEnd, nil)

	// Reflect → Manager（反思后重新规划）
	g.AddEdge(NodeIDReflect, NodeIDManager, nil)

	return g
}
