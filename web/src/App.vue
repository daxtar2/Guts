<template>
  <el-container>
    <el-aside width="200px">
      <el-menu
        router
        :default-active="$route.path"
        class="el-menu-vertical"
      >
        <img src="@/assets/guts.png" alt="Guts Logo" class="logo" width="200" height="120">
        <el-menu-item index="/about">
          <el-icon><InfoFilled /></el-icon>
          <span>关于</span>
        </el-menu-item>
        <el-menu-item index="/scan-results">
          <el-icon><Document /></el-icon>
          <span>扫描结果</span>
        </el-menu-item>
        <el-menu-item index="/filter-config">
          <el-icon><Setting /></el-icon>
          <span>扫描配置</span>
        </el-menu-item>
        <el-menu-item index="/logs">
          <el-icon><List /></el-icon>
          <span>日志查看</span>
        </el-menu-item>
        <el-menu-item index="/templates">
          <el-icon><Files /></el-icon>
          <span>模板管理</span>
        </el-menu-item>
        <el-menu-item index="/template-config">
          <el-icon><Setting /></el-icon>
          <span>模板配置</span>
        </el-menu-item>
        <el-menu-item index="/path-fuzz">
          <el-icon><Link /></el-icon>
          <span>路径字典</span>
        </el-menu-item>

      </el-menu>
    </el-aside>
    <el-main>
      <router-view></router-view>
    </el-main>
  </el-container>
</template>

<script>
import { Document, Setting, List, Files, Link, InfoFilled } from '@element-plus/icons-vue'

export default {
  name: 'App',
  components: {
    Document,
    Setting,
    List,
    Files,
    Link,
    InfoFilled
  }
}
</script>

<style>
.el-container {
  height: 100vh;
}

.el-aside {
  background-color: #304156;
}

.el-menu {
  border-right: none;
}

.el-menu-vertical {
  height: 100%;
  background-color: #304156;
}

.el-menu-item {
  color: #bfcbd9;
}

.el-menu-item.is-active {
  color: #409EFF;
  /* background-color: #263445; */
}

.el-menu-item:hover {
  background-color: #263445;
}

.el-main {
  background-color: #f0f2f5;
  padding: 20px;
}
</style>


