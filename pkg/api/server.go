package api

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
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

		// 获取模板配置
		api.GET("/config/template", server.GetTemplateConfig)

		// 更新模板配置
		api.POST("/config/template", server.UpdateTemplateConfig)

		// 模板管理相关路由
		api.GET("/templates", server.GetTemplatesList)           // 获取模板列表
		api.GET("/templates/*path", server.GetTemplateContent)   // 获取模板内容
		api.POST("/templates/*path", server.SaveTemplateContent) // 保存模板内容
		api.DELETE("/templates/*path", server.DeleteTemplate)    // 删除模板

		// 获取扫描结果的统计信息
		api.GET("/scan/stats", server.GetScanStats)
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
	results, total, err := s.redisManager.Client.GetScanResultsByPage(page, pageSize)
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

// GetFilterConfig 获取当前过滤配置
func (s *Server) GetFilterConfig(c *gin.Context) {
	logger.Info("收到获取配置请求")

	// 确保配置已加载
	if config.GConfig == nil {
		logger.Error("全局配置为空")
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Configuration not initialized",
		})
		return
	}

	// 构建返回数据
	responseData := gin.H{
		"includedomain": config.GConfig.Mitmproxy.IncludeDomain,
		"excludedomain": config.GConfig.Mitmproxy.ExcludeDomain,
		"filtersuffix":  config.GConfig.Mitmproxy.FilterSuffix,
		"addr_port":     config.GConfig.Mitmproxy.AddrPort,
		"ssl_insecure":  config.GConfig.Mitmproxy.SslInsecure,
	}

	// 记录详细的配置信息
	logger.Info("返回过滤配置",
		zap.Any("includedomain", responseData["includedomain"]),
		zap.Any("excludedomain", responseData["excludedomain"]),
		zap.Any("filtersuffix", responseData["filtersuffix"]),
		zap.String("addr_port", responseData["addr_port"].(string)),
		zap.Bool("ssl_insecure", responseData["ssl_insecure"].(bool)),
	)

	c.JSON(200, gin.H{
		"status": "success",
		"data":   responseData,
	})
}

// UpdateFilterConfig 更新流量过滤配置
func (s *Server) UpdateFilterConfig(c *gin.Context) {
	var newConfig models.MitmproxyConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		logger.Error("解析配置JSON失败", zap.Error(err))
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 记录接收到的配置
	logger.Info("收到新的过滤配置",
		zap.Any("includedomain", newConfig.IncludeDomain),
		zap.Any("excludedomain", newConfig.ExcludeDomain),
		zap.Any("filtersuffix", newConfig.FilterSuffix),
		zap.String("addr_port", newConfig.AddrPort),
		zap.Bool("ssl_insecure", newConfig.SslInsecure),
	)

	// 确保所有字段都有值
	if newConfig.FilterSuffix == nil {
		newConfig.FilterSuffix = []string{}
	}
	if newConfig.IncludeDomain == nil {
		newConfig.IncludeDomain = []string{}
	}
	if newConfig.ExcludeDomain == nil {
		newConfig.ExcludeDomain = []string{}
	}

	// 更新内存中的配置
	config.GConfig.Mitmproxy = newConfig

	// 保存到配置文件
	if err := config.SaveConfigToFile(config.GConfig); err != nil {
		logger.Error("保存配置到文件失败", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to save config to file"})
		return
	}

	// 记录配置更新成功
	logger.Info("配置更新成功",
		zap.Any("new_config", newConfig),
		zap.String("client_ip", c.ClientIP()),
	)

	// 返回更新后的配置
	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Filter configuration updated",
		"data": gin.H{
			"includedomain": newConfig.IncludeDomain,
			"excludedomain": newConfig.ExcludeDomain,
			"filtersuffix":  newConfig.FilterSuffix,
			"addr_port":     newConfig.AddrPort,
			"ssl_insecure":  newConfig.SslInsecure,
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

// 获取模板配置
func (s *Server) GetTemplateConfig(c *gin.Context) {
	logger.Info("收到获取模板配置请求")

	// 直接从全局配置获取
	templateConfig := config.GConfig.GetTemplateFilters()
	logger.Info("返回模板配置", zap.Any("config", templateConfig))

	c.JSON(200, gin.H{
		"status": "success",
		"data":   gin.H{"templateConfig": templateConfig},
	})
}

// 更新模板配置
func (s *Server) UpdateTemplateConfig(c *gin.Context) {
	var newConfig models.TemplateFilterConfig
	if err := c.BindJSON(&newConfig); err != nil {
		logger.Error("解析模板配置JSON失败", zap.Error(err))
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// 更新内存中的配置
	config.GConfig.TemplateFilter = newConfig

	// 保存到配置文件
	if err := config.SaveTemplateConfigToFile(&newConfig); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save config to file"})
		return
	}

	// 保存到 Redis
	if err := s.redisManager.SaveConfig(config.GConfig); err != nil {
		logger.Error("保存配置到Redis失败", zap.Error(err))
		// 继续执行，不返回错误
	}

	logger.Info("模板配置更新成功", zap.Any("new_config", newConfig))

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Template configuration updated",
	})
}

// GetTemplatesList 获取模板列表
func (s *Server) GetTemplatesList(c *gin.Context) {
	dirPath := c.Query("path")
	if dirPath == "" {
		dirPath = "templates"
	}

	// 获取完整路径
	fullPath := filepath.Join(".", dirPath)

	// 读取目录内容
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		logger.Error("读取模板目录失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to read templates directory",
		})
		return
	}

	var items []gin.H
	for _, entry := range entries {
		item := gin.H{
			"name":  entry.Name(),
			"isDir": entry.IsDir(),
			"path":  filepath.Join(dirPath, entry.Name()),
		}

		if !entry.IsDir() {
			// 如果是文件，检查是否是 YAML 文件
			if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
				items = append(items, item)
			}
		} else {
			items = append(items, item)
		}
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data":   items,
	})
}

// GetTemplateContent 获取模板内容
func (s *Server) GetTemplateContent(c *gin.Context) {
	filePath := c.Param("path")
	if filePath == "" {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Path parameter is required",
		})
		return
	}

	// 获取完整路径，使用templates目录作为基础
	var fullPath string
	if strings.HasPrefix(filePath, "templates/") {
		// 如果已经包含templates前缀，直接使用
		fullPath = filepath.Clean(filepath.Join(".", filePath))
	} else {
		// 否则添加templates前缀
		fullPath = filepath.Clean(filepath.Join(".", "templates", filePath))
	}

	logger.Info("获取模板内容", zap.String("filePath", filePath), zap.String("fullPath", fullPath))

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// 文件不存在，尝试使用绝对路径
		templatesBasePath := config.GetTemplateBasePath()
		if strings.HasPrefix(filePath, "templates/") {
			// 去除templates/前缀
			relativePath := strings.TrimPrefix(filePath, "templates/")
			fullPath = filepath.Join(templatesBasePath, relativePath)
		} else {
			fullPath = filepath.Join(templatesBasePath, filePath)
		}

		logger.Info("尝试使用绝对路径", zap.String("fullPath", fullPath))
	}

	// 读取文件内容
	content, err := os.ReadFile(fullPath)
	if err != nil {
		logger.Error("读取模板文件失败", zap.Error(err), zap.String("path", fullPath))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to read template file: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"status": "success",
		"data": gin.H{
			"content": string(content),
			"path":    filePath,
		},
	})
}

// SaveTemplateContent 保存模板内容
func (s *Server) SaveTemplateContent(c *gin.Context) {
	filePath := c.Param("path")
	if filePath == "" {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Path parameter is required",
		})
		return
	}

	var req struct {
		Content     string `json:"content"`
		IsDirectory bool   `json:"isDirectory"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	// 获取完整路径
	fullPath := filepath.Join(".", filePath)

	// 如果是目录
	if req.IsDirectory {
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			logger.Error("创建目录失败", zap.Error(err))
			c.JSON(500, gin.H{
				"status":  "error",
				"message": "Failed to create directory",
			})
			return
		}
		c.JSON(200, gin.H{
			"status":  "success",
			"message": "Directory created successfully",
		})
		return
	}

	// 确保父目录存在
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		logger.Error("创建父目录失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to create parent directory",
		})
		return
	}

	// 保存文件内容
	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		logger.Error("保存模板文件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to save template file",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Template saved successfully",
	})
}

// DeleteTemplate 删除模板文件或目录
func (s *Server) DeleteTemplate(c *gin.Context) {
	filePath := c.Param("path")
	if filePath == "" {
		c.JSON(400, gin.H{
			"status":  "error",
			"message": "Path parameter is required",
		})
		return
	}

	// 获取完整路径
	fullPath := filepath.Join(".", filePath)

	// 检查是否是目录
	fileInfo, err1 := os.Stat(fullPath)
	if err1 != nil {
		logger.Error("获取文件信息失败", zap.Error(err1))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to get file info",
		})

	}

	var err error
	if fileInfo.IsDir() {
		// 删除目录
		err = os.RemoveAll(fullPath)
	} else {
		// 删除文件
		err = os.Remove(fullPath)
	}

	if err != nil {
		logger.Error("删除失败", zap.Error(err))
		c.JSON(500, gin.H{
			"status":  "error",
			"message": "Failed to delete",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  "success",
		"message": "Deleted successfully",
	})
}

// GetScanStats 获取扫描结果的统计信息
func (s *Server) GetScanStats(c *gin.Context) {
	logger.Info("获取扫描结果统计信息")

	// 从Redis获取严重程度统计
	stats, err := s.redisManager.Client.GetSeverityStats()
	if err != nil {
		logger.Error("获取扫描结果统计失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  "获取扫描结果统计失败",
		})
		return
	}

	// 获取总结果数
	total := 0
	for _, count := range stats {
		total += count
	}

	logger.Info("成功获取扫描结果统计",
		zap.Int("total", total),
		zap.Any("stats", stats))

	// 返回统计信息
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data": gin.H{
			"total": total,
			"stats": stats,
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
