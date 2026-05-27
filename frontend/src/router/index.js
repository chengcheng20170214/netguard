import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', name: 'Login', component: () => import('../views/Login.vue'), meta: { requiresAuth: false } },
  { path: '/', name: 'Dashboard', component: () => import('../views/Dashboard.vue'), meta: { requiresAuth: true } },
  { path: '/host-discovery', name: 'HostDiscovery', component: () => import('../views/HostDiscovery.vue'), meta: { requiresAuth: true, roles: ['admin', 'auditor'] } },
  { path: '/service-discovery', name: 'ServiceDiscovery', component: () => import('../views/ServiceDiscovery.vue'), meta: { requiresAuth: true, roles: ['admin', 'auditor'] } },
  { path: '/assets', name: 'Assets', component: () => import('../views/Assets.vue'), meta: { requiresAuth: true } },
  { path: '/assets/:id', name: 'AssetDetail', component: () => import('../views/AssetDetail.vue'), meta: { requiresAuth: true } },
  { path: '/vulns', name: 'Vulns', component: () => import('../views/Vulns.vue'), meta: { requiresAuth: true } },
  { path: '/users', name: 'Users', component: () => import('../views/Users.vue'), meta: { requiresAuth: true, roles: ['admin'] } },
  { path: '/settings', name: 'Settings', component: () => import('../views/Settings.vue'), meta: { requiresAuth: true, roles: ['admin'] } }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (to.meta.requiresAuth !== false && !token) {
    next('/login')
  } else if (to.path === '/login' && token) {
    next('/')
  } else {
    const user = JSON.parse(localStorage.getItem('user') || '{}')
    if (to.meta.roles && to.meta.roles.length && !to.meta.roles.includes(user.role)) {
      next('/')
    } else {
      next()
    }
  }
})

export default router
