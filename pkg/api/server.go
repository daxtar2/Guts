package api

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/cache"
	"github.com/daxtar2/Guts/pkg/logger"
	"github.com/daxtar2/Guts/pkg/models"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Server struct {
	router       *gin.Engine
	redisManager *cache.RedisManager
}

func NewServer(redisAddr string) *Server {
	//gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	logger.Info("开始创建API服务")

	// 创建Redis管理器
	redisManager := cache.NewRedisManager(redisAddr)
	logger.Info("Redis管理器创建完成", zap.String("redis_addr", redisAddr))

	server := &Server{
		router:       r,
		redisManager: redisManager,
	}

	// 监听配置变更
	configWrapper, err := server.redisManager.LoadConfigWrapper()
	if err != nil {
		logger.Error("加载配置Wrapper失败", zap.Error(err))
		// 不要在这里返回错误，继续执行
	}

	if configWrapper == nil {
		logger.Error("配置Wrapper为空")
	} else {
		// 设置配置变更监听
		configWrapper.WatchConfig(func(config *models.Config) {
			if config == nil {
				logger.Warn("收到空配置更新")
				return
			}
			logger.Info("收到配置更新", zap.Any("config", config))
		})
		logger.Info("配置变更监听器设置完成")
	}

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
	logger.Info("API路由设置完成")

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
	var newConfig models.MitmproxyConfig
	if err := c.BindJSON(&newConfig); err != nil {
		logger.Error("解析配置JSON失败", zap.Error(err))
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

	logger.Info("配置更新成功",
		zap.Any("new_config", newConfig),
		zap.String("client_ip", c.ClientIP()),
	)

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Filter configuration updated",
	})
}

// GetFilterConfig 获取当前过滤配置
func (s *Server) GetFilterConfig(c *gin.Context) {
	// 首先尝试从 Redis 获取配置
	configWrapper, err := s.redisManager.LoadConfigWrapper()
	if err != nil {
		logger.Warn("从Redis加载配置失败，将使用全局配置", zap.Error(err))
		// 使用全局配置
		c.JSON(200, gin.H{
			"status": "success",
			"data":   config.GConfig.Mitmproxy,
		})
		return
	}

	// 从ConfigWrapper获取配置
	conf, err := configWrapper.LoadConfig()
	if err != nil {
		logger.Error("加载配置失败", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to load config"})
		return
	}

	// 返回配置
	c.JSON(200, gin.H{
		"status": "success",
		"data":   conf.Mitmproxy,
	})
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	// 添加静态文件服务
	s.router.Static("/static", "./web/dist")
	s.router.StaticFile("/", "./web/dist/index.html")

	return s.router.Run(addr)
}
