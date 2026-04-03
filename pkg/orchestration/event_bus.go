package orchestration

import (
	"context"
	"sync"
	"time"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"go.uber.org/zap"
)

// EventType 系统事件类型
type EventType string

const (
	EventGraphChanged      EventType = "graph_changed"      // 知识图谱发生变化
	EventVulnFound         EventType = "vuln_found"         // 发现漏洞
	EventCredFound         EventType = "cred_found"         // 发现凭据/Token
	EventChainDetected     EventType = "chain_detected"     // 漏洞链构建触发
	EventReflectTriggered  EventType = "reflect_triggered"  // 触发反思
	EventPhaseTransition   EventType = "phase_transition"   // 阶段切换
	EventTaskCompleted     EventType = "task_completed"     // 任务完成
	EventTaskFailed        EventType = "task_failed"        // 任务失败
	EventScanComplete      EventType = "scan_complete"      // 扫描完成
)

// Event 系统事件
type Event struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	Type      EventType              `json:"type"`
	Source    models.AgentRole       `json:"source"`    // 事件来源智能体
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt time.Time              `json:"created_at"`
}

// EventHandler 事件处理函数
type EventHandler func(ctx context.Context, event *Event) error

// EventBus 事件驱动总线
type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]EventHandler
	buffer   chan *Event
	done     chan struct{}
}

// NewEventBus 创建新的事件总线
func NewEventBus(bufferSize int) *EventBus {
	if bufferSize <= 0 {
		bufferSize = 256
	}
	return &EventBus{
		handlers: make(map[EventType][]EventHandler),
		buffer:   make(chan *Event, bufferSize),
		done:     make(chan struct{}),
	}
}

// Subscribe 订阅事件类型
func (b *EventBus) Subscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Publish 发布事件
func (b *EventBus) Publish(event *Event) {
	select {
	case b.buffer <- event:
	default:
		logger.Warn("事件总线缓冲区已满，丢弃事件",
			zap.String("event_type", string(event.Type)),
			zap.String("session_id", event.SessionID))
	}
}

// Start 启动事件总线（在 goroutine 中运行）
func (b *EventBus) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-b.done:
				return
			case event := <-b.buffer:
				b.dispatch(ctx, event)
			}
		}
	}()
}

// Stop 停止事件总线
func (b *EventBus) Stop() {
	close(b.done)
}

// dispatch 分发事件给已注册的处理器
func (b *EventBus) dispatch(ctx context.Context, event *Event) {
	b.mu.RLock()
	handlers := b.handlers[event.Type]
	b.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			logger.Error("事件处理失败",
				zap.String("event_type", string(event.Type)),
				zap.String("session_id", event.SessionID),
				zap.Error(err))
		}
	}
}

// NewEvent 构建事件
func NewEvent(sessionID string, eventType EventType, source models.AgentRole, payload map[string]interface{}) *Event {
	return &Event{
		ID:        generateEventID(),
		SessionID: sessionID,
		Type:      eventType,
		Source:    source,
		Payload:   payload,
		CreatedAt: time.Now(),
	}
}

// generateEventID 生成唯一事件ID
func generateEventID() string {
	return "evt_" + time.Now().Format("20060102150405.000000000")
}
