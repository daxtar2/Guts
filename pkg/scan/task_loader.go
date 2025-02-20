package scan

import (
	"fmt"

	"github.com/daxtar2/Guts/pkg/header"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// 加载 Workflow 模板的方法
// func (t *Task) loadWorkflowWithRedis() []*templates.Template {
// 	var workflows []*templates.Template

// 	if t.useRedis {
// 		// 如果 Redis 启用，通过 Redis 加载
// 		workflows, err := t.templateCache.GetWorkflows()
// 		if err != nil || len(workflows) == 0 {
// 			gologger.Warning().Msgf("[Redis Workflow 加载失败] 切换到默认加载方式: %v", err)
// 			workflows = t.loadDefaultWorkflows() // 使用默认方式加载
// 		} else {
// 			gologger.Info().Msgf("[Redis 加载完成] 加载 Workflow 数量: %d", len(workflows))
// 		}
// 	} else {
// 		// 如果 Redis 未启用，直接使用默认加载器
// 		workflows = t.loadDefaultWorkflows()
// 	}

// 	return workflows
// }

// // 默认方式加载 Workflow 模板
// func (t *Task) loadDefaultWorkflows() []*templates.Template {
// 	store := t.engine.Store()
// 	workflows := store.Workflows() // 从本地模板 Store 加载 Workflow
// 	gologger.Info().Msgf("[默认加载] 加载 Workflow 数量: %d", len(workflows))
// 	return workflows
// }

// templatesLoaderwithredis
func (t *Task) RedisLoader(result *header.PassiveResult) []*templates.Template {
	techTemplates, err := t.templateCache.MGetTemplates(getTechTemplateKeys(result.TechStack))
	if err != nil {
		gologger.Warning().Msgf("Redis加载模板失败，切换到默认加载方式: %v", err)
	}
	return techTemplates
}

// getTechTemplateKeys 根据技术栈生成 Redis 模板键名
func getTechTemplateKeys(techStack map[string][]string) []string {
	keys := make([]string, 0) // 初始化空的键列表

	// 遍历每个主机以及对应的技术栈
	for _, techs := range techStack {
		for _, tech := range techs {
			// 将主机的技术栈元素转换为 Redis 键，例如 "template:wordpress"
			key := fmt.Sprintf("template:%s", tech)
			keys = append(keys, key)
		}
	}
	return keys // 返回拼接好的 Redis 键名列表
}
