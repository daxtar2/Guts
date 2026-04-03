package tests

import (
	"context"
	"testing"
	"time"

	"github.com/daxtar2/Guts/pkg/models"
	"github.com/daxtar2/Guts/pkg/orchestration"
)

// TestLangGraphAddNode tests node registration.
func TestLangGraphAddNode(t *testing.T) {
	g := orchestration.NewLangGraph()

	node := &orchestration.GraphNode{
		ID:      orchestration.NodeIDManager,
		Name:    "Manager Agent",
		IsEntry: true,
		Execute: func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
			return state, nil
		},
	}

	if err := g.AddNode(node); err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	// Adding the same node again should fail
	if err := g.AddNode(node); err == nil {
		t.Error("expected error when adding duplicate node")
	}
}

// TestLangGraphExecution tests a simple two-node graph execution.
func TestLangGraphExecution(t *testing.T) {
	g := orchestration.NewLangGraph()
	ctx := context.Background()

	executed := make([]string, 0)

	entryFn := func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
		executed = append(executed, "entry")
		state.SetPhase(orchestration.PhaseScan)
		return state, nil
	}

	endNode := &orchestration.GraphNode{
		ID:    orchestration.NodeIDEnd,
		Name:  "End",
		IsEnd: true,
		Execute: func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
			return state, nil
		},
	}

	entryNode := &orchestration.GraphNode{
		ID:      orchestration.NodeIDManager,
		Name:    "Entry",
		IsEntry: true,
		Execute: entryFn,
	}

	_ = g.AddNode(entryNode)
	_ = g.AddNode(endNode)

	// Entry → End (unconditional)
	g.AddEdge(orchestration.NodeIDManager, orchestration.NodeIDEnd, nil)

	state := orchestration.NewGlobalState("test-session", "example.com")
	finalState, err := g.Execute(ctx, state)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if finalState.Phase != orchestration.PhaseScan {
		t.Errorf("expected Phase %s, got %s", orchestration.PhaseScan, finalState.Phase)
	}
	if len(executed) != 1 || executed[0] != "entry" {
		t.Errorf("expected ['entry'], got %v", executed)
	}
}

// TestLangGraphConditionalEdge tests conditional routing.
func TestLangGraphConditionalEdge(t *testing.T) {
	g := orchestration.NewLangGraph()
	ctx := context.Background()

	managerFn := func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
		// Route to nuclei when there are discovered hosts
		if len(state.DiscoveredHosts) > 0 {
			state.SetNextNode(orchestration.NodeIDNuclei)
		} else {
			state.SetNextNode(orchestration.NodeIDEnd)
		}
		return state, nil
	}

	nucleiFn := func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
		state.SetPhase(orchestration.PhaseScan)
		return state, nil
	}

	_ = g.AddNode(&orchestration.GraphNode{
		ID: orchestration.NodeIDManager, Name: "Manager", IsEntry: true, Execute: managerFn,
	})
	_ = g.AddNode(&orchestration.GraphNode{
		ID: orchestration.NodeIDNuclei, Name: "Nuclei", Execute: nucleiFn,
	})
	_ = g.AddNode(&orchestration.GraphNode{
		ID: orchestration.NodeIDEnd, Name: "End", IsEnd: true, Execute: func(ctx context.Context, state *orchestration.GlobalState) (*orchestration.GlobalState, error) {
			return state, nil
		},
	})

	// Conditional edge from manager
	g.AddConditionalEdge(orchestration.NodeIDManager, func(state *orchestration.GlobalState) orchestration.NodeID {
		return state.NextNode
	})
	// Nuclei → End
	g.AddEdge(orchestration.NodeIDNuclei, orchestration.NodeIDEnd, nil)

	// Without hosts: should skip nuclei → go to End
	state := orchestration.NewGlobalState("test-cond-1", "example.com")
	finalState, err := g.Execute(ctx, state)
	if err != nil {
		t.Fatalf("Execute (no hosts) failed: %v", err)
	}
	if finalState.Phase != orchestration.PhaseInit {
		t.Errorf("without hosts, phase should remain Init, got %s", finalState.Phase)
	}

	// With hosts: should route through Nuclei → PhaseScan
	state2 := orchestration.NewGlobalState("test-cond-2", "example.com")
	state2.AddHost(models.HostEntity{IP: "1.2.3.4", Status: "up", FirstSeen: time.Now(), LastSeen: time.Now()})
	finalState2, err := g.Execute(ctx, state2)
	if err != nil {
		t.Fatalf("Execute (with hosts) failed: %v", err)
	}
	if finalState2.Phase != orchestration.PhaseScan {
		t.Errorf("with hosts, expected PhaseScan, got %s", finalState2.Phase)
	}
}

// TestEventBusPublishSubscribe tests basic event bus functionality.
func TestEventBusPublishSubscribe(t *testing.T) {
	bus := orchestration.NewEventBus(16)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	received := make(chan *orchestration.Event, 1)
	bus.Subscribe(orchestration.EventVulnFound, func(ctx context.Context, event *orchestration.Event) error {
		received <- event
		return nil
	})

	bus.Start(ctx)
	defer bus.Stop()

	event := orchestration.NewEvent("session-001", orchestration.EventVulnFound, models.RoleNuclei,
		map[string]interface{}{"vuln_id": "vuln-001"})
	bus.Publish(event)

	select {
	case e := <-received:
		if e.SessionID != "session-001" {
			t.Errorf("expected session-001, got %s", e.SessionID)
		}
		if e.Source != models.RoleNuclei {
			t.Errorf("expected RoleNuclei, got %s", e.Source)
		}
	case <-time.After(1 * time.Second):
		t.Error("event handler was not called within 1 second")
	}
}

// TestEventBusMultipleSubscribers tests that all subscribers receive the event.
func TestEventBusMultipleSubscribers(t *testing.T) {
	bus := orchestration.NewEventBus(16)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	count := 0
	handler := func(ctx context.Context, event *orchestration.Event) error {
		count++
		return nil
	}

	bus.Subscribe(orchestration.EventGraphChanged, handler)
	bus.Subscribe(orchestration.EventGraphChanged, handler)

	bus.Start(ctx)
	defer bus.Stop()

	event := orchestration.NewEvent("session-002", orchestration.EventGraphChanged, models.RoleMemory, nil)
	bus.Publish(event)

	time.Sleep(200 * time.Millisecond)

	if count != 2 {
		t.Errorf("expected 2 handler invocations, got %d", count)
	}
}
