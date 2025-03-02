import { createRouter, createWebHistory } from 'vue-router'
import ScanResults from '../components/ScanResults.vue'
import FilterConfig from '../components/FilterConfig.vue'

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
    }
]

const router = createRouter({
    history: createWebHistory(),
    routes
})

export default router 