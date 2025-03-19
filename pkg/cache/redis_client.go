package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/daxtar2/Guts/pkg/models"
)

// SaveScanResult 保存扫描结果到 Redis
func (r *RedisClient) SaveScanResult(result *models.ScanResult) error {
	// 生成唯一键
	// 使用URL+漏洞名称作为唯一标识，避免重复存储
	uniqueKey := fmt.Sprintf("%s:%s", result.Target, result.Name)

	// 检查是否已存在相同结果
	exists, err := r.client.Exists(context.Background(), "scan_result:"+uniqueKey).Result()
	if err != nil {
		return fmt.Errorf("检查重复结果失败: %v", err)
	}

	// 如果已存在，则不重复存储或更新时间戳
	if exists > 0 {
		// 可选：更新时间戳
		r.client.HSet(context.Background(), "scan_result:"+uniqueKey, "timestamp", time.Now().Unix())
		return nil
	}

	// 序列化结果
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("序列化扫描结果失败: %v", err)
	}

	// 保存结果
	err = r.client.Set(context.Background(), "scan_result:"+uniqueKey, resultJSON, 0).Err()
	if err != nil {
		return fmt.Errorf("保存扫描结果失败: %v", err)
	}

	// 添加到索引集合
	err = r.client.SAdd(context.Background(), "scan_results_index", uniqueKey).Err()
	if err != nil {
		return fmt.Errorf("添加到索引失败: %v", err)
	}

	return nil
}

// GetScanResults 获取扫描结果，支持时间过滤
func (r *RedisClient) GetScanResultsByPage(page, pageSize int) ([]*models.ScanResult, int64, error) {
	// 获取所有结果键
	keys, err := r.client.SMembers(context.Background(), "scan_results_index").Result()
	if err != nil {
		return nil, 0, fmt.Errorf("获取结果索引失败: %v", err)
	}

	var results []*models.ScanResult
	var total int64 = 0

	// 计算分页
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > len(keys) {
		end = len(keys)
	}

	// 获取指定范围的结果
	for i := start; i < end && i < len(keys); i++ {
		key := keys[i]
		resultJSON, err := r.client.Get(context.Background(), "scan_result:"+key).Result()
		if err != nil {
			continue
		}

		var result models.ScanResult
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			continue
		}

		results = append(results, &result)
		total++
	}

	return results, total, nil
}

// GetSeverityStats 获取按严重程度统计的扫描结果
func (r *RedisClient) GetSeverityStats() (map[string]int, error) {
	// 获取所有结果键
	keys, err := r.client.SMembers(context.Background(), "scan_results_index").Result()
	if err != nil {
		return nil, fmt.Errorf("获取结果索引失败: %v", err)
	}

	// 按严重程度统计
	stats := make(map[string]int)

	// 初始化常见的严重程度类别
	stats["critical"] = 0
	stats["high"] = 0
	stats["medium"] = 0
	stats["low"] = 0
	stats["info"] = 0
	stats["unknown"] = 0

	// 获取所有结果并统计
	for _, key := range keys {
		resultJSON, err := r.client.Get(context.Background(), "scan_result:"+key).Result()
		if err != nil {
			continue
		}

		var result models.ScanResult
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			continue
		}

		// 统计各个严重程度
		severity := strings.ToLower(result.Severity)
		if severity == "" {
			severity = "unknown"
		}

		stats[severity]++
	}

	return stats, nil
}
