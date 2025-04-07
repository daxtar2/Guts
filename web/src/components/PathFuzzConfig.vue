<template>
  <div class="path-fuzz-config">
    <el-card class="box-card">
      <template #header>
        <div class="card-header">
          <span>路径字典配置</span>
          <el-switch
            v-model="config.enabled"
            active-text="启用"
            inactive-text="禁用"
            @change="handleEnableChange"
          />
        </div>
      </template>

      <div class="path-list">
        <div class="path-header">
          <h3>路径列表</h3>
          <el-button type="primary" @click="handleAddPath">添加路径</el-button>
        </div>

        <el-table :data="config.paths" style="width: 100%">
          <el-table-column prop="path" label="路径">
            <template #default="scope">
              <el-input v-model="scope.row" placeholder="请输入路径" />
            </template>
          </el-table-column>
          <el-table-column width="120">
            <template #default="scope">
              <el-button type="danger" @click="handleDeletePath(scope.$index)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <div class="actions">
          <el-button type="primary" @click="handleSave">保存配置</el-button>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script>
import axios from 'axios'
import { ElMessage } from 'element-plus'

export default {
  name: 'PathFuzzConfig',
  data() {
    return {
      config: {
        enabled: false,
        paths: []
      }
    }
  },
  created() {
    this.loadConfig()
  },
  methods: {
    async loadConfig() {
      try {
        const response = await axios.get('/api/config/pathfuzz')
        if (response.data.status === 'success') {
          this.config = response.data.data
        }
      } catch (error) {
        ElMessage.error('加载配置失败')
        console.error('加载配置失败:', error)
      }
    },
    async handleSave() {
      try {
        const response = await axios.post('/api/config/pathfuzz', this.config)
        if (response.data.status === 'success') {
          ElMessage.success('配置保存成功')
        }
      } catch (error) {
        ElMessage.error('保存配置失败')
        console.error('保存配置失败:', error)
      }
    },
    handleAddPath() {
      this.config.paths.push('')
    },
    handleDeletePath(index) {
      this.config.paths.splice(index, 1)
    },
    async handleEnableChange(value) {
      await this.handleSave()
    }
  }
}
</script>

<style scoped>
.path-fuzz-config {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.path-list {
  margin-top: 20px;
}

.path-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.actions {
  margin-top: 20px;
  text-align: right;
}
</style> 