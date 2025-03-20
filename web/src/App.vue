<template>
  <el-container>
    <el-aside width="200px">
      <el-menu router>
        <el-menu-item index="/scan/results">
          扫描结果
        </el-menu-item>
        <el-menu-item index="/config/filter">
          扫描配置
        </el-menu-item>
        <el-menu-item index="/logs">
          日志查看
        </el-menu-item>
        <el-menu-item index="/config/template">
          模板配置
        </el-menu-item>
        <el-menu-item index="/templates">
          模板管理
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-main>
      <router-view></router-view>
    </el-main>
  </el-container>
</template>

<style scoped>
.el-container {
  height: 100vh;
}
.el-aside {
  background-color: #f5f7fa;
}
</style>


