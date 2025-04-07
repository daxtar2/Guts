import { createRouter, createWebHistory } from 'vue-router'
import ScanResults from '../components/ScanResults.vue'
import FilterConfig from '../components/FilterConfig.vue'
import LogViewer from '../components/LogViewer.vue'
import TemplateConfig from '../components/TemplateConfig.vue'
import TemplatesManager from '../components/TemplatesManager.vue'
import PathFuzzConfig from '../components/PathFuzzConfig.vue'
import About from '../components/About.vue'

const routes = [
    {
        path: '/',
        redirect: '/scan-results'
    },
    {
        path: '/scan-results',
        name: 'ScanResults',
        component: ScanResults
    },
    {
        path: '/filter-config',
        name: 'FilterConfig',
        component: FilterConfig
    },
    {
        path: '/logs',
        name: 'LogViewer',
        component: LogViewer
    },
    {
        path: '/templates',
        name: 'TemplatesManager',
        component: TemplatesManager
    },
    {
        path: '/template-config',
        name: 'TemplateConfig',
        component: TemplateConfig
    },
    {
        path: '/path-fuzz',
        name: 'PathFuzzConfig',
        component: PathFuzzConfig
    },
    {
        path: '/about',
        name: 'About',
        component: About
    }
]

const router = createRouter({
    history: createWebHistory(),
    routes
})

export default router 