<template>
  <div class="about-container">
    <div class="about-content">
      <div class="logo-container">
        <img src="@/assets/guts.png" alt="Guts Logo" class="logo">
      </div>
      
      <div class="author-info">

        <p class="contact-info">
          <span class="label">Author：</span>
          <span class="value">Doppel</span><br>
          <span class="label">WeChat：</span>
          <span class="value">whoami779</span>
        </p>
        <p class="contact-info">
          <span class="label">GitHub：</span>
          <a href="https://github.com/daxtar2/Guts" target="_blank" class="value">@daxtar2/Guts</a>
        </p>
      </div>

      <div class="project-info">
        <h2>项目介绍</h2>
        <p class="description">
          Guts 是一个基于 Nuclei 开发的被动扫描器，集成了 Nuclei 扫描引擎，提供被动代理和主动扫描能力。
          该平台采用前后端分离架构，支持实时扫描结果展示、漏洞管理、模板管理等功能。
        </p>
        
        <div class="features">
          <h3>主要特性</h3>
          <ul>
            <li>🔍 智能扫描：支持被动扫描和主动扫描，基于 Nuclei 引擎的漏洞检测</li>
            <li>🎯 BurpSuite 集成：提供 BurpSuite 插件，实时流量分析</li>
            <li>📊 结果管理：实时扫描结果展示，漏洞严重程度统计</li>
            <li>🛠️ 模板管理：支持自定义扫描模板，模板分类管理</li>
            <li>🔒 安全特性：支持域名黑白名单，文件类型过滤</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'About'
}
</script>

<style scoped>
.about-container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: #ffffff;
  color: #ffffff;
  padding: 2rem;
}

.about-content {
  max-width: 800px;
  text-align: center;
  padding: 2rem;
  background-color: #dddddd;
  border-radius: 10px;
  box-shadow: 0 4px 6px rgba(237, 69, 69, 0.1);
}

.logo-container {
  margin-bottom: 2rem;
}

.logo {
  max-width: 400px;
  height: auto;
}

.author-info {
  margin-bottom: 2rem;
}

.author-name {
  font-size: 1.5rem;
  font-weight: bold;
  margin: 1rem 0;
}

.contact-info {
  margin: 0.5rem 0;
  font-size: 1.1rem;
}

.label {
  color: #0000009b;
  margin-right: 0.5rem;
}

.value {
  color: #000000;
}

.value a {
  color: #4a9eff;
  text-decoration: none;
}

.value a:hover {
  text-decoration: underline;
}

.project-info {
  text-align: left;
}

.description {
  margin: 1rem 0;
  line-height: 1.6;
  color: #000000;
}

.features {
  margin-top: 2rem;
}

.features h3 {
  margin-bottom: 1rem;
  color: #000000;
}

.features ul {
  list-style-type: none;
  padding: 0;
}

.features li {
  margin: 0.5rem 0;
  padding: 0.5rem;
  background-color: #ffffff;
  border-radius: 5px;
  transition: background-color 0.3s;
  color: #000000;
}

.features li:hover {
  background-color: #ffffff;
}

h2 {
  color: #000000;
  margin-bottom: 1rem;
}
</style> 