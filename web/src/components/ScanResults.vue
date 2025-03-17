<template>
  <div class="scan-results">
    <h2>扫描结果</h2>
    
    <!-- 结果统计卡片 -->
    <el-row :gutter="20" class="statistics">
      <el-col :span="6" v-for="(stat, severity) in statistics" :key="severity">
        <el-card :class="['stat-card', severity.toLowerCase()]">
          <div class="stat-content">
            <div class="stat-number">{{ stat }}</div>
            <div class="stat-label">{{ severity }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 结果列表 -->
    <el-table :data="scanResults" style="width: 100%" v-loading="loading">
      <el-table-column prop="timestamp" label="时间" width="180">
        <template #default="scope">
          {{ formatDate(scope.row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="host" label="目标" width="180" />
      <el-table-column prop="name" label="漏洞名称" />
      <el-table-column prop="severity" label="严重程度" width="100">
        <template #default="scope">
          <el-tag :type="getSeverityType(scope.row.severity)">
            {{ scope.row.severity }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="120">
        <template #default="scope">
          <el-button type="primary" size="small" @click="showDetail(scope.row)">
            详情
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
      />
    </div>

    <!-- 详情对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="currentVuln.name"
      width="60%"
    >
      <div class="vuln-detail">
        <div class="detail-item">
          <div class="label">目标:</div>
          <div class="value">{{ currentVuln.host }}</div>
        </div>
        <div class="detail-item">
          <div class="label">类型:</div>
          <div class="value">{{ currentVuln.type }}</div>
        </div>
        <div class="detail-item">
          <div class="label">匹配位置:</div>
          <div class="value">{{ currentVuln.matched_at }}</div>
        </div>
        <div class="detail-item">
          <div class="label">描述:</div>
          <div class="value description">{{ currentVuln.description }}</div>
        </div>
        <div class="detail-item">
          <div class="label">标签:</div>
          <div class="value">
            <el-tag
              v-for="tag in currentVuln.tags"
              :key="tag"
              class="tag"
              size="small"
            >
              {{ tag }}
            </el-tag>
          </div>
        </div>
        <div class="detail-item">
          <div class="label">参考链接:</div>
          <div class="value">
            <a
              v-for="ref in currentVuln.reference"
              :key="ref"
              :href="ref"
              target="_blank"
              class="reference"
            >
              {{ ref }}
            </a>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

export default defineComponent({
  name: 'ScanResults',
  setup() {
    const scanResults = ref([])
    const currentPage = ref(1)
    const pageSize = ref(10)
    const total = ref(0)
    const loading = ref(false)
    const dialogVisible = ref(false)
    const currentVuln = ref({})
    const statistics = ref({
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
    })

    const loadResults = async () => {
      loading.value = true
      try {
        const response = await axios.get('/api/scan/results', {
          params: {
            page: currentPage.value,
            pageSize: pageSize.value,
          },
        })
        console.log('API Response:', response.data)
        
        if (response.data.status === 'success') {
          scanResults.value = response.data.data.results
          total.value = response.data.data.total
          updateStatistics(response.data.data.results)
        } else {
          ElMessage.warning('获取扫描结果失败')
        }
      } catch (error) {
        console.error('加载扫描结果失败:', error)
        ElMessage.error('加载扫描结果失败')
      } finally {
        loading.value = false
      }
    }

    const updateStatistics = (results) => {
      // 重置统计
      Object.keys(statistics.value).forEach(key => {
        statistics.value[key] = 0
      })
      
      // 统计各严重程度的数量
      results.forEach(result => {
        if (statistics.value.hasOwnProperty(result.severity)) {
          statistics.value[result.severity]++
        }
      })
    }

    const handleSizeChange = (val) => {
      pageSize.value = val
      loadResults()
    }

    const handleCurrentChange = (val) => {
      currentPage.value = val
      loadResults()
    }

    const showDetail = (vuln) => {
      currentVuln.value = vuln
      dialogVisible.value = true
    }

    const formatDate = (date) => {
      return new Date(date).toLocaleString()
    }

    const getSeverityType = (severity) => {
      const types = {
        'critical': 'danger',
        'high': 'error',
        'medium': 'warning',
        'low': 'info',
      }
      return types[severity.toLowerCase()] || 'info'
    }

    onMounted(() => {
      loadResults()
      // 每30秒刷新一次结果
      const timer = setInterval(loadResults, 30000)
      
      // 组件卸载时清理定时器
      onUnmounted(() => {
        if (timer) {
          clearInterval(timer)
        }
      })
    })

    return {
      scanResults,
      currentPage,
      pageSize,
      total,
      loading,
      dialogVisible,
      currentVuln,
      statistics,
      handleSizeChange,
      handleCurrentChange,
      showDetail,
      formatDate,
      getSeverityType,
    }
  },
})
</script>

<style scoped>
.scan-results {
  padding: 20px;
}

.statistics {
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
}

.stat-card.critical { background-color: #fef0f0; }
.stat-card.high { background-color: #fdf6ec; }
.stat-card.medium { background-color: #fdf6ec; }
.stat-card.low { background-color: #f0f9eb; }

.stat-content {
  padding: 10px;
}

.stat-number {
  font-size: 24px;
  font-weight: bold;
}

.stat-label {
  margin-top: 5px;
  color: #666;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: center;
}

.vuln-detail .detail-item {
  margin-bottom: 15px;
}

.vuln-detail .label {
  font-weight: bold;
  margin-bottom: 5px;
}

.vuln-detail .value {
  color: #666;
}

.vuln-detail .description {
  white-space: pre-wrap;
}

.vuln-detail .tag {
  margin-right: 5px;
  margin-bottom: 5px;
}

.vuln-detail .reference {
  display: block;
  color: #409EFF;
  margin-bottom: 5px;
}

.vuln-detail .reference:hover {
  text-decoration: underline;
}
</style> 