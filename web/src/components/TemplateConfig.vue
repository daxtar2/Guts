<template>
  <div class="template-config">
    <h2>模板配置</h2>
    <el-form :model="formState" @submit.prevent="onFinish">
      <!-- 严重程度 -->
      <el-form-item label="严重程度">
        <el-select
          v-model="formState.severity"
          multiple
          placeholder="选择严重程度"
          style="width: 100%"
        >
          <el-option
            v-for="item in severityOptions"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
      </el-form-item>

      <!-- 排除严重程度 -->
      <el-form-item label="排除严重程度">
        <el-select
          v-model="formState.excludeSeverities"
          multiple
          placeholder="选择要排除的严重程度"
          style="width: 100%"
        >
          <el-option
            v-for="item in severityOptions"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
      </el-form-item>

      <!-- 协议类型 -->
      <el-form-item label="协议类型">
        <el-select
          v-model="formState.protocolTypes"
          multiple
          placeholder="选择协议类型"
          style="width: 100%"
        >
          <el-option
            v-for="item in protocolOptions"
            :key="item"
            :label="item"
            :value="item"
          />
        </el-select>
      </el-form-item>

      <!-- 标签 -->
      <el-form-item label="标签">
        <el-select
          v-model="formState.tags"
          multiple
          filterable
          allow-create
          default-first-option
          placeholder="输入标签"
          style="width: 100%"
        />
      </el-form-item>

      <!-- 作者 -->
      <el-form-item label="作者">
        <el-select
          v-model="formState.authors"
          multiple
          filterable
          allow-create
          default-first-option
          placeholder="输入作者"
          style="width: 100%"
        />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" @click="onFinish">保存配置</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

export default defineComponent({
  name: 'TemplateConfig',
  setup() {
    const formState = ref({
      severity: [],
      excludeSeverities: [],
      protocolTypes: [],
      authors: [],
      tags: [],
      excludeTags: [],
      includeTags: [],
      ids: [],
      excludeIds: [],
      templateCondition: [],
    })

    const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
    const protocolOptions = ['http', 'dns', 'file', 'tcp', 'headless']

    // 加载配置
    const loadConfig = async () => {
      try {
        const response = await axios.get('/api/config/template')
        console.log('Template config response:', response.data) // 调试日志
        
        if (response.data.status === 'success' && response.data.data.templateConfig) {
          const config = response.data.data.templateConfig
          console.log('Received template config:', config) // 调试日志
          
          formState.value = {
            severity: config.Severity ? config.Severity.split(',') : [],
            excludeSeverities: config.ExcludeSeverities ? config.ExcludeSeverities.split(',') : [],
            protocolTypes: config.ProtocolTypes ? config.ProtocolTypes.split(',') : [],
            excludeProtocolTypes: config.ExcludeProtocolTypes ? config.ExcludeProtocolTypes.split(',') : [],
            authors: config.Authors || [],
            tags: config.Tags || [],
            excludeTags: config.ExcludeTags || [],
            includeTags: config.IncludeTags || [],
            ids: config.IDs || [],
            excludeIds: config.ExcludeIDs || [],
            templateCondition: config.TemplateCondition || [],
          }
          console.log('Updated formState:', formState.value) // 调试日志
        }
      } catch (error) {
        ElMessage.error('加载模板配置失败')
        console.error('加载模板配置失败:', error)
      }
    }

    // 保存配置
    const onFinish = async () => {
      try {
        const submitData = {
          ...formState.value,
          severity: formState.value.severity.join(','),
          excludeSeverities: formState.value.excludeSeverities.join(','),
          protocolTypes: formState.value.protocolTypes.join(','),
          excludeProtocolTypes: formState.value.excludeProtocolTypes.join(','),
        }
        
        const response = await axios.post('/api/config/template', submitData)
        if (response.data.status === 'success') {
          ElMessage.success('配置更新成功')
          await loadConfig()
        }
      } catch (error) {
        ElMessage.error('保存配置失败')
        console.error('保存配置失败:', error)
      }
    }

    onMounted(() => {
      loadConfig()
    })

    return {
      formState,
      severityOptions,
      protocolOptions,
      onFinish,
    }
  },
})
</script>

<style scoped>
.template-config {
  padding: 20px;
}
</style> 