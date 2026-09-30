<template>
  <el-card>
    <div class="toolbar">
      <el-input v-model="keyword" placeholder="用户名或邮箱" style="width: 200px" />
      <el-select v-model="role" clearable placeholder="角色" style="width: 140px">
        <el-option label="管理员" value="ADMIN" /><el-option label="普通用户" value="USER" />
      </el-select>
      <el-select v-model="status" clearable placeholder="状态" style="width: 120px">
        <el-option label="启用" :value="1" /><el-option label="禁用" :value="0" />
      </el-select>
      <el-button type="primary" @click="load(1)">查询</el-button>
      <el-button @click="openCreate">新增用户</el-button>
    </div>
    <el-table :data="rows">
      <el-table-column prop="username" label="账号" />
      <el-table-column prop="email" label="邮箱" />
      <el-table-column label="角色"><template #default="{ row }">{{ row.roles.join("、") }}</template></el-table-column>
      <el-table-column label="状态" width="80"><template #default="{ row }">{{ row.status ? "启用" : "禁用" }}</template></el-table-column>
      <el-table-column prop="created_at" label="注册时间" width="170" />
      <el-table-column prop="last_login_at" label="最后登录" width="170" />
      <el-table-column label="操作" width="180">
        <template #default="{ row }">
          <el-button link @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination layout="prev, pager, next" :total="total" :page-size="10" style="margin-top:12px" @current-change="load" />
    <el-dialog v-model="visible" :title="form.id ? '编辑用户' : '新增用户'" width="480px">
      <el-form label-width="90px">
        <el-form-item label="用户名"><el-input v-model="form.username" :disabled="!!form.id" /></el-form-item>
        <el-form-item label="邮箱"><el-input v-model="form.email" /></el-form-item>
        <el-form-item label="昵称"><el-input v-model="form.nickname" /></el-form-item>
        <el-form-item label="联系方式"><el-input v-model="form.phone" /></el-form-item>
        <el-form-item :label="form.id ? '重置密码' : '密码'"><el-input v-model="form.password" type="password" show-password /></el-form-item>
        <el-form-item label="状态" v-if="form.id">
          <el-switch v-model="enabled" active-text="启用" inactive-text="禁用" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.role_codes" multiple>
            <el-option label="管理员" value="ADMIN" /><el-option label="普通用户" value="USER" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer><el-button type="primary" @click="save">保存</el-button></template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import http from "../../api/http";

const keyword = ref("");
const role = ref("");
const status = ref<number | undefined>();
const rows = ref<any[]>([]);
const total = ref(0);
const visible = ref(false);
const enabled = ref(true);
const form = reactive<any>({ id: 0, username: "", email: "", nickname: "", phone: "", password: "", role_codes: ["USER"] });

async function load(page = 1) {
  const { data } = await http.get("/admin/users", { params: { keyword: keyword.value, role: role.value, status: status.value, page, size: 10 } });
  rows.value = data.items;
  total.value = data.total;
}
function openCreate() {
  Object.assign(form, { id: 0, username: "", email: "", nickname: "", phone: "", password: "", role_codes: ["USER"] });
  visible.value = true;
}
function openEdit(row: any) {
  Object.assign(form, { ...row, password: "", role_codes: [...row.roles] });
  enabled.value = row.status === 1;
  visible.value = true;
}
async function save() {
  const payload = { ...form, status: enabled.value ? 1 : 0 };
  if (!payload.password) delete payload.password;
  if (form.id) await http.put(`/admin/users/${form.id}`, payload);
  else await http.post("/admin/users", payload);
  visible.value = false;
  ElMessage.success("已保存");
  await load(1);
}
async function remove(row: any) {
  await ElMessageBox.confirm(`删除用户 ${row.username}？`, "确认");
  await http.delete(`/admin/users/${row.id}`);
  ElMessage.success("已删除");
  await load(1);
}
load(1);
</script>
