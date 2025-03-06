package cache

import (
	"github.com/daxtar2/Guts/pkg/models"
)

// ConfigInterface 定义配置的基本操作
type ConfigInterface interface {
	LoadConfig() (*models.Config, error)
	SaveConfig(*models.Config) error
}
