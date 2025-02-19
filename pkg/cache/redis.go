package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/redis/go-redis/v9"
)

type TemplateCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewTemplateCache(addr string) *TemplateCache {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})

	return &TemplateCache{
		client: client,
		ttl:    24 * time.Hour, // 缓存24小时
	}
}

// 存储模板
func (tc *TemplateCache) SetTemplate(key string, tmpl *templates.Template) error {
	data, err := json.Marshal(tmpl)
	if err != nil {
		return err
	}
	return tc.client.Set(context.Background(), key, data, tc.ttl).Err()
}

// 获取模板
func (tc *TemplateCache) GetTemplate(key string) (*templates.Template, error) {
	data, err := tc.client.Get(context.Background(), key).Bytes()
	if err != nil {
		return nil, err
	}

	var tmpl templates.Template
	if err := json.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	return &tmpl, nil
}

// 批量获取模板
func (tc *TemplateCache) MGetTemplates(keys []string) ([]*templates.Template, error) {
	pipe := tc.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))

	for i, key := range keys {
		cmds[i] = pipe.Get(context.Background(), key)
	}

	_, err := pipe.Exec(context.Background())
	if err != nil && err != redis.Nil {
		return nil, err
	}

	templatesSlice := make([]*templates.Template, 0, len(keys))
	for _, cmd := range cmds {
		if data, err := cmd.Bytes(); err == nil {
			var tmpls *templates.Template
			if err := json.Unmarshal(data, &tmpls); err == nil {
				templatesSlice = append(templatesSlice, tmpls)
			}
		}
	}

	return templatesSlice, nil
}
