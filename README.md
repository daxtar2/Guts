# Guts - 基于nuclei的被动扫描器

<div align="center">

![Guts Logo](web/src/assets/logo.png)

[![Go Report Card](https://goreportcard.com/badge/github.com/daxtar2/Guts)](https://goreportcard.com/report/github.com/daxtar2/Guts)
[![License](https://img.shields.io/github/license/daxtar2/Guts)](LICENSE)
[![Release](https://img.shields.io/github/v/release/daxtar2/Guts)](https://github.com/daxtar2/Guts/releases)

</div>

## 📖 项目介绍

Guts 是一个基于nuclei开发的被动扫描器，集成了 BurpSuite 插件和 Nuclei 扫描引擎，提供被动扫描和主动扫描能力。该平台采用前后端分离架构，支持实时扫描结果展示、漏洞管理、模板管理等功能。

## ✨ 主要特性

- 🔍 **智能扫描**
  - 支持被动扫描和主动扫描
  - 基于 Nuclei 引擎的漏洞检测
  - 可配置的扫描速率和并发控制
  - 支持自定义扫描模板

- 🎯 **BurpSuite 集成**
  - 提供 BurpSuite 插件
  - 实时流量分析
  - 自动漏洞检测
  - 扫描结果实时同步

- 📊 **结果管理**
  - 实时扫描结果展示
  - 漏洞严重程度统计
  - 详细的漏洞信息展示
  - 支持漏洞详情查看

- 🛠️ **模板管理**
  - 支持自定义扫描模板
  - 模板分类管理
  - 模板搜索功能
  - 模板导入导出

- 🔒 **安全特性**
  - 支持域名黑白名单
  - 文件类型过滤
  - 扫描速率限制
  - 并发控制

## 🚀 快速开始

### 环境要求

- Go 1.16+
- Redis 6.0+
- Node.js 14+
- BurpSuite Professional

### 安装步骤

1. 克隆项目
```bash
git clone https://github.com/daxtar2/Guts.git
cd Guts
```

2. 安装后端依赖
```bash
go mod download
```

3. 安装前端依赖
```bash
cd web
npm install
```

4. 配置环境
```bash
cp config/config.yaml.example config/config.yaml
# 编辑 config.yaml 配置文件
```

5. 编译项目
```bash
# 编译后端
go build -o guts cmd/main.go

# 编译前端
cd web
npm run build
```

### 运行服务

1. 启动 Redis 服务
```bash
redis-server
```

2. 启动后端服务
```bash
./guts
```

3. 启动前端服务（开发模式）
```bash
cd web
npm run serve
```

## 📝 使用说明

### 1. 配置扫描参数

在 `config/config.yaml` 中配置扫描参数：

```yaml
scan_rate:
  global_rate: 30
  global_rate_unit: "second"
  template_concurrency: 100
  host_concurrency: 100
```

### 2. 安装 BurpSuite 插件

1. 在 BurpSuite 中加载 `burp-extension/target/Guts.jar`
2. 配置插件连接参数
3. 开始使用被动扫描功能

### 3. 使用 Web 界面

1. 访问 `http://localhost:8080`
2. 配置扫描目标
3. 选择扫描模板
4. 开始扫描
5. 查看扫描结果

## 🔧 配置说明

### Redis 配置
```yaml
redis:
  address: "localhost:6379"
  password: ""
  db: 0
```

### 扫描配置
```yaml
scan_rate:
  global_rate: 30
  global_rate_unit: "second"
  template_concurrency: 100
  host_concurrency: 100
```

### 代理配置
```yaml
mitmproxy:
  port: 8080
  include_domains: []
  exclude_domains: []
  filter_suffix: [".jpg", ".png", ".gif"]
```

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。在提交代码前，请确保：

1. 代码符合 Go 代码规范
2. 添加了必要的测试用例
3. 更新了相关文档

## 📄 开源协议

本项目采用 MIT 协议开源，详见 [LICENSE](LICENSE) 文件。

## 👥 作者

- 作者：[Your Name]
- 邮箱：[your.email@example.com]

## 🙏 致谢

感谢以下开源项目：

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [BurpSuite](https://portswigger.net/burp)
- [Element Plus](https://element-plus.org/)
- [Vue.js](https://vuejs.org/) 