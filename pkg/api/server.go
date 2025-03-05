package api

import (
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

		// 获取日志文件列表
		api.GET("/logs", server.GetLogFiles)

		// 获取日志文件内容
		api.GET("/logs/:filename", server.GetLogContent)
	}
	logger.Info("API路由设置完成")

	return server
}

// GetScanResults 获取扫描结果列表
func (s *Server) GetScanResults(c *gin.Context) {
	// 获取分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	logger.Info("获取扫描结果请求",
		zap.Int("page", page),
		zap.Int("pageSize", pageSize))

	// 从Redis获取结果
	results, total, err := s.redisManager.Client.GetScanResults(page, pageSize)
	if err != nil {
		logger.Error("获取扫描结果失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  "获取扫描结果失败",
		})
		return
	}

	logger.Info("成功获取扫描结果",
		zap.Int("total", int(total)),
		zap.Int("results_count", len(results)))

	// 返回符合前端要求的格式
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"results": results,
			"total":   total,
		},
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
	logger.Info("收到获取配置请求")

	// 首先尝试从 Redis 获取配置
	configWrapper, err := s.redisManager.LoadConfigWrapper()
	if err != nil {
		logger.Warn("从Redis加载配置失败，将使用全局配置", zap.Error(err))
		// 使用全局配置
		c.JSON(200, gin.H{
			"status": "success",
			"data": gin.H{
				"includedomain": config.GConfig.Mitmproxy.IncludeDomain,
				"excludedomain": config.GConfig.Mitmproxy.ExcludeDomain,
				"filtersuffix":  config.GConfig.Mitmproxy.FilterSuffix,
				"addr_port":     config.GConfig.Mitmproxy.AddrPort,
				"ssl_insecure":  config.GConfig.Mitmproxy.SslInsecure,
			},
		})
		return
	}

	// 从ConfigWrapper获取配置
	conf, err := configWrapper.LoadConfig()
	if err != nil {
		logger.Error("加载配置失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to load config",
		})
		return
	}

	// 返回配置
	c.JSON(200, gin.H{
		"status": "success",
		"data": gin.H{
			"includedomain": conf.Mitmproxy.IncludeDomain,
			"excludedomain": conf.Mitmproxy.ExcludeDomain,
			"filtersuffix":  conf.Mitmproxy.FilterSuffix,
			"addr_port":     conf.Mitmproxy.AddrPort,
			"ssl_insecure":  conf.Mitmproxy.SslInsecure,
		},
	})
}

// LogFile 日志文件信息
type LogFile struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

// GetLogFiles 获取日志文件列表
func (s *Server) GetLogFiles(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("pageSize", "10")

	pageNum, _ := strconv.Atoi(page)
	size, _ := strconv.Atoi(pageSize)

	// 读取日志目录
	files, err := os.ReadDir("logs")
	if err != nil {
		logger.Error("读取日志目录失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to read logs directory",
		})
		return
	}

	var logFiles []LogFile
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".log") {
			info, err := file.Info()
			if err != nil {
				continue
			}
			logFiles = append(logFiles, LogFile{
				Name:         file.Name(),
				Size:         info.Size(),
				LastModified: info.ModTime(),
			})
		}
	}

	// 计算总页数
	total := len(logFiles)
	totalPages := (total + size - 1) / size

	// 对文件按修改时间排序（最新的在前）
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].LastModified.After(logFiles[j].LastModified)
	})

	// 分页
	start := (pageNum - 1) * size
	end := start + size
	if end > total {
		end = total
	}
	if start >= total {
		start = total
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data": gin.H{
			"files":       logFiles[start:end],
			"total":       total,
			"totalPages":  totalPages,
			"currentPage": pageNum,
			"pageSize":    size,
		},
	})
}

// GetLogContent 获取日志文件内容
func (s *Server) GetLogContent(c *gin.Context) {
	filename := c.Param("filename")

	// 安全检查：确保文件名只包含允许的字符
	if !regexp.MustCompile(`^[\w\-\.]+\.log$`).MatchString(filename) {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Invalid filename",
		})
		return
	}

	filepath := path.Join("logs", filename)
	content, err := os.ReadFile(filepath)
	if err != nil {
		logger.Error("读取日志文件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to read log file",
		})
		return
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data": gin.H{
			"content":  string(content),
			"filename": filename,
		},
	})
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	// 添加静态文件服务
	s.router.Static("/static", "./web/dist")
	s.router.StaticFile("/", "./web/dist/index.html")

	return s.router.Run(addr)
}
