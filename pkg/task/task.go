package task

import (
	"github.com/panjf2000/ants/v2"
	"sync"
)

type Task struct {
	MaxPoolsize int // 最大并发数
	Pool        *ants.Pool
	Wg          *sync.WaitGroup
}
