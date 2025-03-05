package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SaveScanResult 保存扫描结果到 Redis
func (r *RedisClient) SaveScanResult(result *models.ScanResult) error {
	// 序列化结果
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("序列化扫描结果失败: %v", err)
	}

	// 使用 Redis Pipeline 批量执行命令
	pipe := r.client.Pipeline()

	// 保存扫描结果详情
	resultKey := fmt.Sprintf("scan:result:%s", result.ID)
	pipe.Set(context.Background(), resultKey, data, 24*time.Hour)

	// 添加到扫描结果列表
	pipe.LPush(context.Background(), "scan:results", result.ID)
	pipe.LTrim(context.Background(), "scan:results", 0, 999) // 只保留最近1000条结果

	// 按主机分组
	hostKey := fmt.Sprintf("scan:host:%s", result.Host)
	pipe.LPush(context.Background(), hostKey, result.ID)
	pipe.Expire(context.Background(), hostKey, 24*time.Hour)

	// 按漏洞类型分组
	vulnKey := fmt.Sprintf("scan:vuln:%s", result.Name)
	pipe.LPush(context.Background(), vulnKey, result.ID)
	pipe.Expire(context.Background(), vulnKey, 24*time.Hour)

	// 按严重程度分组
	severityKey := fmt.Sprintf("scan:severity:%s", result.Severity)
	pipe.LPush(context.Background(), severityKey, result.ID)
	pipe.Expire(context.Background(), severityKey, 24*time.Hour)

	// 执行 Pipeline
	_, err = pipe.Exec(context.Background())
	if err != nil {
		return fmt.Errorf("保存扫描结果到 Redis 失败: %v", err)
	}

	return nil
}

// GetScanResults 获取扫描结果列表
func (r *RedisClient) GetScanResults(page, pageSize int) ([]*models.ScanResult, int64, error) {
	// 获取结果总数
	total, err := r.client.LLen(context.Background(), "scan:results").Result()
	if err != nil {
		if err == redis.Nil {
			// 如果列表不存在，返回空结果而不是错误
			return []*models.ScanResult{}, 0, nil
		}
		return nil, 0, fmt.Errorf("获取扫描结果总数失败: %v", err)
	}

	// 如果总数为0，直接返回空结果
	if total == 0 {
		return []*models.ScanResult{}, 0, nil
	}

	// 计算分页范围
	start := (page - 1) * pageSize
	end := start + pageSize - 1

	// 获取当前页的结果ID列表
	ids, err := r.client.LRange(context.Background(), "scan:results", int64(start), int64(end)).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("获取扫描结果ID列表失败: %v", err)
	}

	// 如果没有ID，返回空结果
	if len(ids) == 0 {
		return []*models.ScanResult{}, total, nil
	}

	// 批量获取结果详情
	var results []*models.ScanResult
	pipe := r.client.Pipeline()
	for _, id := range ids {
		pipe.Get(context.Background(), fmt.Sprintf("scan:result:%s", id))
	}
	cmders, err := pipe.Exec(context.Background())
	if err != nil && err != redis.Nil {
		return nil, 0, fmt.Errorf("批量获取扫描结果失败: %v", err)
	}

	// 解析结果
	for _, cmder := range cmders {
		cmd := cmder.(*redis.StringCmd)
		data, err := cmd.Bytes()
		if err != nil {
			if err != redis.Nil {
				logger.Warn("获取扫描结果数据失败",
					zap.Error(err))
			}
			continue
		}

		var result models.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			logger.Warn("解析扫描结果失败",
				zap.Error(err),
				zap.ByteString("data", data))
			continue
		}
		results = append(results, &result)
	}

	return results, total, nil
}
