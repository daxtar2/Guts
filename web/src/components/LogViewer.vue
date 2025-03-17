<template>
  <div class="log-viewer">
    <h2>日志查看</h2>
    
    <!-- 日志文件列表 -->
    <el-table :data="logFiles" style="width: 100%">
      <el-table-column prop="name" label="文件名" />
      <el-table-column prop="size" label="大小">
        <template #default="scope">
          {{ formatFileSize(scope.row.size) }}
        </template>
      </el-table-column>
      <el-table-column prop="last_modified" label="最后修改时间">
        <template #default="scope">
          {{ formatDate(scope.row.last_modified) }}
        </template>
      </el-table-column>
      <el-table-column label="操作">
        <template #default="scope">
          <el-button type="primary" @click="viewLogContent(scope.row)">
            查看内容
          </el-button>
        </template>
      </el-table-column>
    </el-table>
    
    <!-- 分页 -->
    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
      />
    </div>
    
    <!-- 日志内容对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="currentLog.name"
      width="80%"
      class="log-content-dialog"
    >
      <pre class="log-content">{{ logContent }}</pre>
    </el-dialog>
  </div>
</template>

<script>
import { defineComponent, ref, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import axios from 'axios';

export default defineComponent({
  name: 'LogViewer',
  setup() {
    const logFiles = ref([]);
    const currentPage = ref(1);
    const pageSize = ref(10);
    const total = ref(0);
    const dialogVisible = ref(false);
    const currentLog = ref({});
    const logContent = ref('');

    const loadLogFiles = async () => {
      try {
        const response = await axios.get('/api/logs', {
          params: {
            page: currentPage.value,
            pageSize: pageSize.value,
          },
        });
        
        if (response.data.status === 'success') {
          logFiles.value = response.data.data.files;
          total.value = response.data.data.total;
        }
      } catch (error) {
        console.error('加载日志列表失败:', error);
        ElMessage.error('加载日志列表失败');
      }
    };

    const viewLogContent = async (log) => {
      try {
        currentLog.value = log;
        const response = await axios.get(`/api/logs/${log.name}`);
        if (response.data.status === 'success') {
          logContent.value = response.data.data.content;
          dialogVisible.value = true;
        }
      } catch (error) {
        console.error('加载日志内容失败:', error);
        ElMessage.error('加载日志内容失败');
      }
    };

    const handleSizeChange = (val) => {
      pageSize.value = val;
      loadLogFiles();
    };

    const handleCurrentChange = (val) => {
      currentPage.value = val;
      loadLogFiles();
    };

    const formatFileSize = (size) => {
      const units = ['B', 'KB', 'MB', 'GB'];
      let index = 0;
      let fileSize = size;
      
      while (fileSize >= 1024 && index < units.length - 1) {
        fileSize /= 1024;
        index++;
      }
      
      return `${fileSize.toFixed(2)} ${units[index]}`;
    };

    const formatDate = (date) => {
      return new Date(date).toLocaleString();
    };

    onMounted(() => {
      loadLogFiles();
    });

    return {
      logFiles,
      currentPage,
      pageSize,
      total,
      dialogVisible,
      currentLog,
      logContent,
      viewLogContent,
      handleSizeChange,
      handleCurrentChange,
      formatFileSize,
      formatDate,
    };
  },
});
</script>

<style scoped>
.log-viewer {
  padding: 20px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: center;
}

.log-content {
  white-space: pre-wrap;
  font-family: monospace;
  background: #f5f5f5;
  padding: 10px;
  border-radius: 4px;
  max-height: 600px;
  overflow-y: auto;
}

.log-content-dialog :deep(.el-dialog__body) {
  padding: 10px 20px;
}
</style> 