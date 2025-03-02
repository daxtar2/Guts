<template>
  <div class="filter-config">
    <h2>流量过滤配置</h2>
    
    <el-form :model="filterConfig" label-width="120px">
      <!-- 文件类型过滤 -->
      <el-form-item label="文件类型过滤">
        <el-select v-model="filterConfig.filterSuffix" multiple>
          <el-option label=".js" value=".js"></el-option>
          <el-option label=".php" value=".php"></el-option>
          <el-option label=".css" value=".css"></el-option>
          <el-option label=".jpg" value=".jpg"></el-option>
          <el-option label=".png" value=".png"></el-option>
        </el-select>
      </el-form-item>
      
      <!-- 域名白名单 -->
      <el-form-item label="域名白名单">
        <el-input
          v-model="newDomain"
          placeholder="输入域名后回车添加"
          @keyup.enter="addDomain('include')"
        ></el-input>
        <el-tag
          v-for="domain in filterConfig.includeDomain"
          :key="domain"
          closable
          @close="removeDomain(domain, 'include')"
        >
          {{ domain }}
        </el-tag>
      </el-form-item>
      
      <!-- 域名黑名单 -->
      <el-form-item label="域名黑名单">
        <el-input
          v-model="newExcludeDomain"
          placeholder="输入域名后回车添加"
          @keyup.enter="addDomain('exclude')"
        ></el-input>
        <el-tag
          v-for="domain in filterConfig.excludeDomain"
          :key="domain"
          closable
          type="danger"
          @close="removeDomain(domain, 'exclude')"
        >
          {{ domain }}
        </el-tag>
      </el-form-item>
      
      <el-form-item>
        <el-button type="primary" @click="saveConfig">保存配置</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      filterConfig: {
        filterSuffix: [],
        includeDomain: [],
        excludeDomain: [],
      },
      newDomain: '',
      newExcludeDomain: '',
    }
  },
  
  methods: {
    async loadConfig() {
      const response = await fetch('/api/config/filter')
      const data = await response.json()
      this.filterConfig = data.data
    },
    
    async saveConfig() {
      await fetch('/api/config/filter', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(this.filterConfig),
      })
      
      this.$message.success('配置已更新')
    },
    
    addDomain(type) {
      const domain = type === 'include' ? this.newDomain : this.newExcludeDomain
      if (domain) {
        if (type === 'include') {
          this.filterConfig.includeDomain.push(domain)
          this.newDomain = ''
        } else {
          this.filterConfig.excludeDomain.push(domain)
          this.newExcludeDomain = ''
        }
      }
    },
    
    removeDomain(domain, type) {
      if (type === 'include') {
        this.filterConfig.includeDomain = this.filterConfig.includeDomain.filter(d => d !== domain)
      } else {
        this.filterConfig.excludeDomain = this.filterConfig.excludeDomain.filter(d => d !== domain)
      }
    },
  },
  
  mounted() {
    this.loadConfig()
  }
}
</script> 