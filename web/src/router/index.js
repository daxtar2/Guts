import { createRouter, createWebHistory } from 'vue-router'
import ScanResults from '../components/ScanResults.vue'
import FilterConfig from '../components/FilterConfig.vue'
import LogViewer from '../components/LogViewer.vue'
import TemplateConfig from '../components/TemplateConfig.vue'
import TemplatesManager from '../components/TemplatesManager.vue'

const routes = [
    {
        path: '/',
        redirect: '/scan/results'
    },
    {
        path: '/scan/results',
        name: 'ScanResults',
        component: ScanResults
    },
    {
        path: '/config/filter',
        name: 'FilterConfig',
        component: FilterConfig
    },
    {
        path: '/logs',
        name: 'LogViewer',
        component: LogViewer
    },
    {
        path: '/config/template',
        name: 'TemplateConfig',
        component: TemplateConfig
    },
    {
        path: '/templates',
        name: 'Templates',
        component: TemplatesManager
    }
]

const router = createRouter({
    history: createWebHistory(),
    routes
})

export default router 