package api

import (
	"github.com/daxtar2/Guts/config"
	"github.com/daxtar2/Guts/pkg/header"
	"github.com/gin-gonic/gin"
)

type Server struct {
	router         *gin.Engine
	scannedResults map[string]*header.PassiveResult // 用于存储扫描结果
}

func NewServer() *Server {
	r := gin.Default()
	server := &Server{
		router:         r,
		scannedResults: make(map[string]*header.PassiveResult),
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

	return server
}

// 获取扫描结果列表
func (s *Server) GetScanResults(c *gin.Context) {
	results := make([]*header.PassiveResult, 0)
	for _, result := range s.scannedResults {
		results = append(results, result)
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data":   results,
	})
}

// 获取特定扫描结果详情
func (s *Server) GetScanResultDetail(c *gin.Context) {
	id := c.Param("id")
	result, exists := s.scannedResults[id]
	if !exists {
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
	var newConfig config.Mitmproxy
	if err := c.BindJSON(&newConfig); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 更新配置
	config.GConfig.Mitmproxy = newConfig

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Filter configuration updated",
	})
}

// 获取当前过滤配置
func (s *Server) GetFilterConfig(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "success",
		"data":   config.GConfig.Mitmproxy,
	})
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	// 添加静态文件服务
	s.router.Static("/static", "./web/dist")
	s.router.StaticFile("/", "./web/dist/index.html")

	return s.router.Run(addr)
}
