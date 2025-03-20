<template>
  <div class="filter-config">
    <h2>流量过滤配置</h2>
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

  <div class="scan-rate-config-container">
    <h2>扫描速率配置</h2>
    
    <el-form :model="scanRateForm" label-width="180px">
      <el-divider content-position="left">全局速率限制</el-divider>
      <el-form-item label="全局速率 (每单位时间请求数)">
        <el-input-number v-model="scanRateForm.globalrate" :min="1" :max="1000"></el-input-number>
      </el-form-item>
      <el-form-item label="速率单位">
        <el-select v-model="scanRateForm.globalrateunit">
          <el-option label="秒" value="second"></el-option>
          <el-option label="分钟" value="minute"></el-option>
          <el-option label="小时" value="hour"></el-option>
        </el-select>
      </el-form-item>
      
      <el-divider content-position="left">并发设置</el-divider>
      <el-form-item label="模板并发">
        <el-input-number v-model="scanRateForm.templateconcurrency" :min="1" :max="500"></el-input-number>
      </el-form-item>
      <el-form-item label="主机并发">
        <el-input-number v-model="scanRateForm.hostconcurrency" :min="1" :max="500"></el-input-number>
      </el-form-item>
      <el-form-item label="无头浏览器主机并发">
        <el-input-number v-model="scanRateForm.headlesshostconcurrency" :min="1" :max="300"></el-input-number>
      </el-form-item>
      <el-form-item label="无头浏览器模板并发">
        <el-input-number v-model="scanRateForm.headlesstemplateconcurrency" :min="1" :max="300"></el-input-number>
      </el-form-item>
      <el-form-item label="JavaScript模板并发">
        <el-input-number v-model="scanRateForm.javascripttemplateconcurrency" :min="1" :max="300"></el-input-number>
      </el-form-item>
      <el-form-item label="模板载荷并发">
        <el-input-number v-model="scanRateForm.templatepayloadconcurrency" :min="1" :max="200"></el-input-number>
      </el-form-item>
      <el-form-item label="探测并发">
        <el-input-number v-model="scanRateForm.probeconcurrency" :min="1" :max="300"></el-input-number>
      </el-form-item>
      
      <el-form-item>
        <el-button type="primary" @click="saveScanRateConfig">保存扫描速率配置</el-button>
        <el-button @click="resetScanRateConfig">重置</el-button>
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
          addrport: ':7777',
          sslinsecure: true,
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
  data() {
    return {
      scanRateForm: {
        globalrate: 30,
        globalrateunit: 'second',
        templateconcurrency: 100,
        hostconcurrency: 100,
        headlesshostconcurrency: 50,
        headlesstemplateconcurrency: 50,
        javascripttemplateconcurrency: 50,
        templatepayloadconcurrency: 25,
        probeconcurrency: 50
      },
      defaultScanRateConfig: {
        globalrate: 30,
        globalrateunit: 'second',
        templateconcurrency: 100,
        hostconcurrency: 100,
        headlesshostconcurrency: 50,
        headlesstemplateconcurrency: 50,
        javascripttemplateconcurrency: 50,
        templatepayloadconcurrency: 25,
        probeconcurrency: 50
      }
    };
  },
  created() {
    this.fetchScanRateConfig();
  },
  methods: {
    // 获取当前扫描速率配置
    fetchScanRateConfig() {
      axios.get('/api/config/scanrate')
        .then(response => {
          if (response.data.status === 'success') {
            this.scanRateForm = response.data.data;
            // 保存默认值，用于重置
            this.defaultScanRateConfig = { ...response.data.data };
          }
        })
        .catch(error => {
          console.error('获取扫描速率配置失败:', error);
          this.$message.error('获取扫描速率配置失败');
        });
    },
    // 保存扫描速率配置
    saveScanRateConfig() {
      axios.post('/api/config/scanrate', this.scanRateForm)
        .then(response => {
          if (response.data.status === 'success') {
            ElMessage.success('扫描速率配置已更新');
            // 更新默认值
            this.defaultScanRateConfig = { ...this.scanRateForm };
          } else {
            ElMessage.error(response.data.message || '保存失败');
          }
        })
        .catch(error => {
          console.error('保存扫描速率配置失败:', error);
          ElMessage.error('保存扫描速率配置失败');
        });
    },
    // 重置表单
    resetScanRateConfig() {
      this.scanRateForm = { ...this.defaultScanRateConfig };
    }
  }
});
</script>

<style scoped>
.filter-config {
  padding: 20px;
}

.ant-form-item {
  margin-bottom: 24px;
}

.scan-rate-config-container {
  margin-top: 20px;
  padding: 20px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  background-color: #fff;
}

h2 {
  margin-bottom: 24px;
}
</style> 