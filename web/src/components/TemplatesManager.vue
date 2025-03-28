<template>
  <div class="templates-manager">
    <div class="templates-tree">
      <h2>Templates管理</h2>

      <div class="header-actions">
        <el-button-group>
          <el-button 
            type="primary" 
            @click="showCreateDialog('file')"
            size="small"
          >
            <el-icon><Document /></el-icon>
            新建文件
          </el-button>
          <el-button 
            type="primary" 
            @click="showCreateDialog('directory')"
            size="small"
          >
            <el-icon><Folder /></el-icon>
            新建目录
          </el-button>
        </el-button-group>

        <el-button 
          v-if="currentPath !== 'templates'"
          @click="navigateBack"
          type="primary"
          plain
          size="small"
        >
          <el-icon><ArrowLeft /></el-icon>
          返回上一级
        </el-button>

        <!-- 添加搜索框和搜索按钮 -->
        <div class="search-box">
          <el-input
            v-model="searchQuery"
            placeholder="搜索文件或目录..."
            :prefix-icon="Search"
            clearable
            size="small"
          />
          <el-button 
            type="primary" 
            @click="handleSearch"
            size="small"
          >
            搜索
          </el-button>
        </div>
      </div>

      <!-- 搜索结果列表 -->
      <div v-if="searchResults.length > 0" class="search-results">
        <h3>搜索结果</h3>
        <el-table :data="searchResults" style="width: 100%">
          <el-table-column prop="name" label="名称">
            <template #default="{ row }">
              <el-button 
                link 
                type="primary" 
                @click="handleSearchResultClick(row)"
              >
                <el-icon v-if="row.isDir"><Folder /></el-icon>
                <el-icon v-else><Document /></el-icon>
                {{ row.name }}
              </el-button>
            </template>
          </el-table-column>
          <el-table-column prop="path" label="路径" />
          <el-table-column prop="type" label="类型" width="100">
            <template #default="{ row }">
              {{ row.isDir ? '目录' : '文件' }}
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- 创建文件/目录对话框 -->
      <el-dialog
        v-model="createDialogVisible"
        :title="createType === 'file' ? '新建文件' : '新建目录'"
        width="30%"
      >
        <el-form :model="createForm" label-width="80px">
          <el-form-item :label="createType === 'file' ? '文件名' : '目录名'">
            <el-input 
              v-model="createForm.name"
              :placeholder="createType === 'file' ? '请输入文件名 (例如: test.yaml)' : '请输入目录名'"
            />
          </el-form-item>
        </el-form>
        <template #footer>
          <span class="dialog-footer">
            <el-button @click="createDialogVisible = false">取消</el-button>
            <el-button type="primary" @click="handleCreate">创建</el-button>
          </span>
        </template>
      </el-dialog>

      <el-table v-if="!searchResults.length" :data="templates" style="width: 100%">
        <el-table-column prop="name" label="名称">
          <template #default="{ row }">
            <el-button 
              link 
              type="primary" 
              @click="handleItemClick(row)"
            >
              <el-icon v-if="row.isDir"><Folder /></el-icon>
              <el-icon v-else><Document /></el-icon>
              {{ row.name }}
            </el-button>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="100">
          <template #default="{ row }">
            {{ row.isDir ? '目录' : '文件' }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" align="center">
          <template #default="{ row }">
            <el-popconfirm
              :title="`确定要删除${row.isDir ? '目录' : '文件'} ${row.name} 吗？`"
              @confirm="handleDelete(row)"
            >
              <template #reference>
                <el-button 
                  type="danger" 
                  size="small"
                  :icon="Delete"
                  circle
                />
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div v-if="selectedTemplate" class="template-editor">
      <div class="editor-header">
        <div class="editor-title">
          <h3>{{ selectedTemplate.name }}</h3>
          <el-button
            type="danger"
            class="close-btn"
            @click="closeTemplate"
            size="small"
            circle
          >
            <el-icon><Close /></el-icon>
          </el-button>
        </div>
        <el-button type="primary" @click="saveTemplate">保存</el-button>
      </div>
      <el-input
        v-model="templateContent"
        type="textarea"
        :rows="20"
        class="template-content"
      />
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'
import { Folder, Document, ArrowLeft, Close, Plus, Delete, Search } from '@element-plus/icons-vue'

export default {
  name: 'TemplatesManager',
  components: { Folder, Document, ArrowLeft, Close, Plus, Delete, Search },
  
  setup() {
    const templates = ref([])
    const currentPath = ref('templates')
    const selectedTemplate = ref(null)
    const templateContent = ref('')
    const createDialogVisible = ref(false)
    const createType = ref('file')
    const createForm = ref({
      name: '',
    })
    const searchQuery = ref('')
    const searchResults = ref([])

    const pathParts = computed(() => {
      return currentPath.value.split('/').slice(1)
    })

    // 加载目录内容
    const loadTemplates = async (path = 'templates') => {
      try {
        const response = await axios.get(`/api/templates?path=${path}`)
        if (response.data.status === 'success') {
          templates.value = response.data.data
          currentPath.value = path
        }
      } catch (error) {
        ElMessage.error('加载模板列表失败')
        console.error('加载模板列表失败:', error)
      }
    }

    // 处理点击事件
    const handleItemClick = async (item) => {
      if (item.isDir) {
        await loadTemplates(item.path)
      } else {
        try {
          const path = item.path.replace(/^templates\//, '')
          const response = await axios.get(`/api/templates/content/${path}`)
          if (response.data.status === 'success') {
            selectedTemplate.value = item
            templateContent.value = response.data.data.content
          }
        } catch (error) {
          ElMessage.error('加载模板内容失败')
          console.error('加载模板内容失败:', error)
        }
      }
    }

    // 保存模板
    const saveTemplate = async () => {
      if (!selectedTemplate.value) return

      try {
        const path = selectedTemplate.value.path.replace(/^templates\//, '')
        const response = await axios.post(
          `/api/templates/content/${path}`,
          { content: templateContent.value }
        )
        if (response.data.status === 'success') {
          ElMessage.success('保存成功')
        }
      } catch (error) {
        ElMessage.error('保存模板失败')
        console.error('保存模板失败:', error)
      }
    }

    // 导航到根目录
    const navigateToRoot = () => {
      loadTemplates()
    }

    // 导航到指定路径
    const navigateToPath = (index) => {
      const newPath = ['templates', ...pathParts.value.slice(0, index + 1)].join('/')
      loadTemplates(newPath)
    }

    // 返回上一级目录
    const navigateBack = () => {
      const pathParts = currentPath.value.split('/')
      pathParts.pop() // 移除最后一个部分
      const parentPath = pathParts.join('/')
      loadTemplates(parentPath)
    }

    // 关闭模板
    const closeTemplate = () => {
      selectedTemplate.value = null
      templateContent.value = ''
    }

    // 显示创建对话框
    const showCreateDialog = (type) => {
      createType.value = type
      createForm.value.name = ''
      createDialogVisible.value = true
    }

    // 处理创建文件/目录
    const handleCreate = async () => {
      if (!createForm.value.name) {
        ElMessage.warning('请输入名称')
        return
      }

      // 如果是文件，确保有.yaml后缀
      if (createType.value === 'file' && !createForm.value.name.endsWith('.yaml')) {
        createForm.value.name += '.yaml'
      }

      // 手动拼接路径
      const newPath = currentPath.value === 'templates'
        ? createForm.value.name
        : `${currentPath.value.replace(/^templates\//, '')}/${createForm.value.name}`
      
      // 规范化路径分隔符
      const normalizedPath = newPath.replace(/\\/g, '/')

      try {
        if (createType.value === 'directory') {
          // 创建目录
          await axios.post(`/api/templates/${normalizedPath}`, { isDirectory: true })
          ElMessage.success('目录创建成功')
          loadTemplates(currentPath.value)
        } else {
          // 创建文件
          const defaultContent = `id: ${createForm.value.name.replace('.yaml', '')}\ninfo:\n  name: New Template\n  severity: info\n`
          await axios.post(`/api/templates/${normalizedPath}`, { 
            content: defaultContent,
            isDirectory: false 
          })
          ElMessage.success('文件创建成功')
          
          // 自动打开新创建的文件
          selectedTemplate.value = { name: createForm.value.name, path: normalizedPath }
          templateContent.value = defaultContent
        }
        createDialogVisible.value = false
      } catch (error) {
        ElMessage.error('创建失败')
        console.error('创建失败:', error)
      }
    }

    // 处理删除
    const handleDelete = async (item) => {
      try {
        // 移除路径中重复的 'templates/' 前缀
        const path = item.path.replace(/^templates\//, '')
        const response = await axios.delete(`/api/templates/content/${path}`)
        if (response.data.status === 'success') {
          ElMessage.success('删除成功')
          // 如果正在编辑这个文件，关闭编辑器
          if (selectedTemplate.value && selectedTemplate.value.path === item.path) {
            closeTemplate()
          }
          // 重新加载当前目录
          loadTemplates(currentPath.value)
        }
      } catch (error) {
        ElMessage.error('删除失败')
        console.error('删除失败:', error)
      }
    }

    // 处理搜索
    const handleSearch = async () => {
      if (!searchQuery.value) {
        searchResults.value = []
        return
      }

      try {
        const response = await axios.get(`/api/templates/search?query=${encodeURIComponent(searchQuery.value)}`)
        if (response.data.status === 'success') {
          searchResults.value = response.data.data
        }
      } catch (error) {
        ElMessage.error('搜索失败')
        console.error('搜索失败:', error)
      }
    }

    // 处理搜索结果点击
    const handleSearchResultClick = async (item) => {
      if (item.isDir) {
        await loadTemplates(item.path)
        searchQuery.value = ''
        searchResults.value = []
      } else {
        try {
          const path = item.path.replace(/^templates\//, '')
          const response = await axios.get(`/api/templates/content/${path}`)
          if (response.data.status === 'success') {
            selectedTemplate.value = item
            templateContent.value = response.data.data.content
            searchQuery.value = ''
            searchResults.value = []
          }
        } catch (error) {
          ElMessage.error('加载模板内容失败')
          console.error('加载模板内容失败:', error)
        }
      }
    }

    // 初始加载
    loadTemplates()

    return {
      templates,
      currentPath,
      pathParts,
      selectedTemplate,
      templateContent,
      createDialogVisible,
      createType,
      createForm,
      searchQuery,
      searchResults,
      loadTemplates,
      handleItemClick,
      saveTemplate,
      navigateToRoot,
      navigateToPath,
      navigateBack,
      closeTemplate,
      showCreateDialog,
      handleCreate,
      handleDelete,
      handleSearch,
      handleSearchResultClick,
      Delete, // 导出图标以供模板使用
    }
  },
}
</script>

<style scoped>
.templates-manager {
  display: flex;
  gap: 20px;
  padding: 20px;
  height: calc(100vh - 100px);
}

.templates-tree {
  flex: 1;
  overflow-y: auto;
}

.template-editor {
  flex: 2;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.editor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.editor-title {
  display: flex;
  align-items: center;
  gap: 10px;
  position: relative;
}

.close-btn {
  position: absolute;
  right: -40px;
  top: 50%;
  transform: translateY(-50%);
  transition: all 0.3s;
}

.template-content {
  flex: 1;
  font-family: monospace;
}

.breadcrumb {
  margin-bottom: 20px;
  font-size: 16px;
}

.header-actions {
  display: flex;
  margin-bottom: 10px;
  gap: 10px;
}

.search-box {
  flex: 1;
  max-width: 300px;
  display: flex;
  gap: 8px;
}

.search-results {
  margin-top: 20px;
}

:deep(.el-breadcrumb__item) {
  cursor: pointer;
}
</style> 