package scan

import (
	"fmt"
	"github.com/daxtar2/Guts/config"
	"github.com/panjf2000/ants/v2"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"golang.org/x/net/context"
	"sync"
	"time"
)

type Task struct {
	MaxPoolsize int // 最大并发数
	Pool        *ants.Pool
	Wg          *sync.WaitGroup
}

func (t Task) ScanBegin() {
	ctx, err := context.WithTimeout(context.Background(), time.Duration(t.MaxPoolsize)*time.Second) // 相当于每个task 1s 暂定
	if err != nil {
		panic(err)
	}
	ne, err2 := nuclei.NewNucleiEngineCtx(ctx, nuclei.WithTemplateFilters(config.GetTemplateFilters()))
	if err2 != nil {
		panic(err2)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err3 := ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
			fmt.Println("+存在漏洞:", event.Host, event.Info.Name)
		}) // 第二个参数是回调函数，每个回调都会收到 *output.ResultEvent，用于处理漏洞扫描结果。可以添加多个callfunc
		if err3 != nil {
			panic(err3)
		}
	}()

	wg.Wait()
	defer ne.Close()

}
