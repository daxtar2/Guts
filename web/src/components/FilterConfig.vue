<template>
  <div class="filter-config">
    <h2>过滤配置</h2>
    <el-form :model="formState" @submit.prevent="onFinish">
      <!-- 包含域名 -->
      <el-form-item label="包含域名">
        <el-select
          v-model="formState.includeDomain"
          multiple
          filterable
          allow-create
          default-first-option
          placeholder="请输入要包含的域名"
          style="width: 100%"
        />
      </el-form-item>

      <!-- 排除域名 -->
      <el-form-item label="排除域名">
        <el-select
          v-model="formState.excludeDomain"
          multiple
          filterable
          allow-create
          default-first-option
          placeholder="请输入要排除的域名"
          style="width: 100%"
        />
      </el-form-item>

      <!-- 过滤后缀 -->
      <el-form-item label="过滤后缀">
        <el-select
          v-model="formState.filterSuffix"
          multiple
          filterable
          allow-create
          default-first-option
          placeholder="请输入要过滤的文件后缀"
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
import { defineComponent, ref, onMounted } from 'vue';
import axios from 'axios';
import { ElMessage } from 'element-plus';

export default defineComponent({
  name: 'FilterConfig',
  setup() {
    const formState = ref({
      includeDomain: [],
      excludeDomain: [],
      filterSuffix: [],
    });

    // 加载配置
    const loadConfig = async () => {
      try {
        const response = await axios.get('/api/config/filter');
        if (response.data.status === 'success') {
          formState.value = {
            includeDomain: response.data.data.includedomain || [],
            excludeDomain: response.data.data.excludedomain || [],
            filterSuffix: response.data.data.filtersuffix || [],
          };
        }
      } catch (error) {
        message.error('加载配置失败');
        console.error('加载配置失败:', error);
      }
    };

    // 保存配置
    const onFinish = async () => {
      try {
        const response = await axios.post('/api/config/filter', {
          includedomain: formState.value.includeDomain,
          excludedomain: formState.value.excludeDomain,
          filtersuffix: formState.value.filterSuffix,
          addr_port: ':7777',
          ssl_insecure: true,
        });
        
        if (response.data.status === 'success') {
          ElMessage.success('配置更新成功');
          await loadConfig();
        }
      } catch (error) {
        ElMessage.error('保存配置失败');
        console.error('保存配置失败:', error);
      }
    };

    // 组件挂载时加载配置
    onMounted(() => {
      loadConfig();
    });

    return {
      formState,
      onFinish,
    };
  },
});
</script>

<style scoped>
.filter-config {
  padding: 20px;
}

.ant-form-item {
  margin-bottom: 24px;
}

h2 {
  margin-bottom: 24px;
}
</style> 