package api

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/gin-gonic/gin"
)

type Server struct {
	router       *gin.Engine
	redisManager *cache.RedisManager
}

func NewServer(redisAddr string) *Server {
	r := gin.Default()

	server := &Server{
		router:       r,
		redisManager: cache.NewRedisManager(redisAddr),
	}

	// 监听配置变更
	configWrapper, _ := server.redisManager.LoadConfigWrapper()
	configWrapper.WatchConfig(func(config *models.Config) {
		// 处理配置变更
	})

	// API 路由
	api := r.Group("/api")
	{
		// 获取扫描结果列表
		api.GET("/scan/results", server.GetScanResults)

		// 获取特定扫描结果详情
		api.GET("/scan/result/:id", server.GetScanResultDetail)

		// 更新流量过滤配置
		api.POST("/config/filter", server.UpdateFilterConfig)

		// 获取当前过滤配置
		api.GET("/config/filter", server.GetFilterConfig)
	}

	return server
}

// 获取扫描结果列表
func (s *Server) GetScanResults(c *gin.Context) {
	// 从 Redis 获取扫描结果列表
	// 这里可以实现获取所有扫描结果的逻辑
	c.JSON(200, gin.H{
		"status": "success",
		"data":   "获取扫描结果的逻辑未实现", // 这里可以返回实际的结果
	})
}

// 获取特定扫描结果详情
func (s *Server) GetScanResultDetail(c *gin.Context) {
	id := c.Param("id")
	result, err := s.redisManager.GetScanResult(id) // 从 Redis 获取扫描结果
	if err != nil {
		c.JSON(404, gin.H{"error": "Result not found"})
		return
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data":   result,
	})
}

// 更新流量过滤配置
func (s *Server) UpdateFilterConfig(c *gin.Context) {
	var newConfig models.Mitmproxy
	if err := c.BindJSON(&newConfig); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 更新内存中的配置
	config.GConfig.Mitmproxy = newConfig

	// 保存到 Redis
	if err := s.redisManager.SaveConfig(config.GConfig); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save config to Redis"})
		return
	}

	// 保存到配置文件
	if err := config.SaveConfigToFile(config.GConfig); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save config to file"})
		return
	}

	// 发布配置更新通知
	if err := s.redisManager.PublishUpdate(config.GConfig); err != nil {
		c.JSON(500, gin.H{"error": "Failed to publish config update"})
		return
	}

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Filter configuration updated",
	})
}

// 获取当前过滤配置
func (s *Server) GetFilterConfig(c *gin.Context) {
	// 从 Redis 获取最新配置
	config, err := s.redisManager.LoadConfigWrapper()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to load config"})
		return
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data":   config.Mitmproxy,
	})
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	// 添加静态文件服务
	s.router.Static("/static", "./web/dist")
	s.router.StaticFile("/", "./web/dist/index.html")

	return s.router.Run(addr)
}
