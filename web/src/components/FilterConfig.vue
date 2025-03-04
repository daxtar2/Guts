<template>
  <div class="filter-config">
    <h2>过滤配置</h2>
    <a-form :model="formState" @finish="onFinish">
      <!-- 包含域名 -->
      <a-form-item label="包含域名">
        <a-select
          v-model:value="formState.includeDomain"
          mode="tags"
          style="width: 100%"
          placeholder="请输入要包含的域名"
        />
      </a-form-item>

      <!-- 排除域名 -->
      <a-form-item label="排除域名">
        <a-select
          v-model:value="formState.excludeDomain"
          mode="tags"
          style="width: 100%"
          placeholder="请输入要排除的域名"
        />
      </a-form-item>

      <!-- 过滤后缀 -->
      <a-form-item label="过滤后缀">
        <a-select
          v-model:value="formState.filterSuffix"
          mode="tags"
          style="width: 100%"
          placeholder="请输入要过滤的文件后缀"
        />
      </a-form-item>

      <a-form-item>
        <a-button type="primary" html-type="submit">保存配置</a-button>
      </a-form-item>
    </a-form>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted } from 'vue';
import { message } from 'ant-design-vue';
import axios from 'axios';

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
    const onFinish = async (values) => {
      try {
        const response = await axios.post('/api/config/filter', {
          includedomain: values.includeDomain,
          excludedomain: values.excludeDomain,
          filtersuffix: values.filterSuffix,
          addr_port: ':9080',
          ssl_insecure: true,
        });
        
        if (response.data.status === 'success') {
          message.success('配置更新成功');
          await loadConfig(); // 重新加载配置
        }
      } catch (error) {
        message.error('保存配置失败');
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