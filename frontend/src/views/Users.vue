<template>
  <div>
    <el-card>
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>用户管理</span>
          <el-button type="primary" size="small" @click="showAddDialog">添加用户</el-button>
        </div>
      </template>
      <el-table :data="users" stripe border>
        <el-table-column prop="username" label="用户名" width="150" />
        <el-table-column prop="email" label="邮箱" width="200" />
        <el-table-column prop="role" label="角色" width="120">
          <template #default="{ row }"><el-tag :type="roleType(row.role)">{{ roleLabel(row.role) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="is_active" label="状态" width="80">
          <template #default="{ row }"><el-tag :type="row.is_active?'success':'danger'">{{ row.is_active ? '启用' : '禁用' }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
            <el-button size="small" @click="editUser(row)">编辑</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    <el-dialog v-model="dialogVisible" :title="isEdit ? '编辑用户' : '添加用户'" width="400px">
      <el-form :model="userForm" label-width="80px">
        <el-form-item label="用户名" v-if="!isEdit"><el-input v-model="userForm.username" /></el-form-item>
        <el-form-item label="邮箱" v-if="!isEdit"><el-input v-model="userForm.email" /></el-form-item>
        <el-form-item label="密码" v-if="!isEdit"><el-input v-model="userForm.password" type="password" /></el-form-item>
        <el-form-item label="角色">
          <el-select v-model="userForm.role">
            <el-option label="管理员" value="admin" />
            <el-option label="审计员" value="auditor" />
            <el-option label="访客" value="guest" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态" v-if="isEdit">
          <el-switch v-model="userForm.is_active" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible=false">取消</el-button>
        <el-button type="primary" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { getUsers, updateUser, deleteUser } from '../api/users'
import { register } from '../api/auth'
import { ElMessage, ElMessageBox } from 'element-plus'

const users = ref([])
const dialogVisible = ref(false)
const isEdit = ref(false)
const editingId = ref(null)
const userForm = reactive({ username: '', email: '', password: '', role: 'auditor', is_active: true })

const roleLabel = (r) => ({ admin: '管理员', auditor: '审计员', guest: '访客' }[r] || r)
const roleType = (r) => ({ admin: 'danger', auditor: '', guest: 'info' }[r] || 'info')

const fetchUsers = async () => {
  const res = await getUsers()
  users.value = res.data.items || res.data || []
}

const showAddDialog = () => {
  isEdit.value = false
  Object.assign(userForm, { username: '', email: '', password: '', role: 'auditor', is_active: true })
  dialogVisible.value = true
}

const editUser = (row) => {
  isEdit.value = true
  editingId.value = row.id
  Object.assign(userForm, { role: row.role, is_active: row.is_active })
  dialogVisible.value = true
}

const handleSave = async () => {
  if (isEdit.value) {
    await updateUser(editingId.value, { role: userForm.role, is_active: userForm.is_active })
    ElMessage.success('用户已更新')
  } else {
    await register(userForm)
    ElMessage.success('用户已创建')
  }
  dialogVisible.value = false
  fetchUsers()
}

const handleDelete = async (row) => {
  await ElMessageBox.confirm('确定删除用户 ' + row.username + '?', '确认')
  await deleteUser(row.id)
  ElMessage.success('已删除')
  fetchUsers()
}

onMounted(fetchUsers)
</script>
