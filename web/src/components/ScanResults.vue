<template>
  <div class="scan-results">
    <h2>扫描结果列表</h2>
    
    <!-- 结果列表 -->
    <el-table :data="scanResults" style="width: 100%">
      <el-table-column prop="host" label="域名"></el-table-column>
      <el-table-column prop="vuln_name" label="漏洞名称"></el-table-column>
      <el-table-column prop="severity" label="严重程度">
        <template #default="scope">
          <el-tag :type="getSeverityType(scope.row.severity)">
            {{ scope.row.severity }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="create_time" label="发现时间"></el-table-column>
      <el-table-column label="操作">
        <template #default="scope">
          <el-button @click="viewDetail(scope.row)">查看详情</el-button>
        </template>
      </el-table-column>
    </el-table>
    
    <!-- 详情弹窗 -->
    <el-dialog v-model="detailVisible" title="扫描结果详情" width="70%">
      <div v-if="selectedResult">
        <h3>基本信息</h3>
        <p>域名：{{ selectedResult.host }}</p>
        <p>端口：{{ selectedResult.port }}</p>
        <p>URL：{{ selectedResult.url }}</p>
        
        <h3>技术栈信息</h3>
        <div v-for="(techs, category) in selectedResult.techStack" :key="category">
          <h4>{{ category }}</h4>
          <el-tag v-for="tech in techs" :key="tech">{{ tech }}</el-tag>
        </div>
        
        <h3>扫描结果</h3>
        <el-table :data="selectedResult.vulnerabilities">
          <el-table-column prop="name" label="漏洞名称"></el-table-column>
          <el-table-column prop="severity" label="严重程度"></el-table-column>
          <el-table-column prop="description" label="描述"></el-table-column>
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script>
export default {
  data() {
    return {
      scanResults: [],
      detailVisible: false,
      selectedResult: null,
    }
  },
  
  methods: {
    async fetchResults() {
      const response = await fetch('/api/scan/results')
      const data = await response.json()
      this.scanResults = data.data
    },
    
    async viewDetail(result) {
      const response = await fetch(`/api/scan/result/${result.id}`)
      const data = await response.json()
      this.selectedResult = data.data
      this.detailVisible = true
    },
    
    getSeverityType(severity) {
      const types = {
        'critical': 'danger',
        'high': 'error',
        'medium': 'warning',
        'low': 'info'
      }
      return types[severity.toLowerCase()] || 'info'
    }
  },
  
  mounted() {
    this.fetchResults()
    // 定期刷新结果
    setInterval(this.fetchResults, 5000)
  }
}
</script> 