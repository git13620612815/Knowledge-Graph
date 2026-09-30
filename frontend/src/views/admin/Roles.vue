<template>
  <el-card>
    <div class="toolbar"><el-button type="primary" @click="openCreate">新增角色</el-button></div>
    <el-table :data="roles">
      <el-table-column prop="code" label="编码" width="140" />
      <el-table-column prop="name" label="名称" width="140" />
      <el-table-column label="父角色" width="140">
        <template #default="{ row }">{{ nameOf(row.parent_role_id) }}</template>
      </el-table-column>
      <el-table-column label="直接权限" min-width="240">
        <template #default="{ row }">{{ row.permissions.join("、") }}</template>
      </el-table-column>
      <el-table-column label="操作" width="160">
        <template #default="{ row }">
          <el-button link @click="openEdit(row)">配置</el-button>
          <el-button v-if="!row.builtin" link type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-dialog v-model="visible" title="角色配置" width="640px">
      <el-form label-width="80px">
        <el-form-item label="编码"><el-input v-model="form.code" :disabled="form.builtin || !!form.id" /></el-form-item>
        <el-form-item label="名称"><el-input v-model="form.name" /></el-form-item>
        <el-form-item label="父角色">
          <el-select v-model="form.parent_role_id" clearable>
            <el-option v-for="item in roles.filter((role) => role.id !== form.id)" :key="item.id" :label="item.name" :value="item.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="备注"><el-input v-model="form.remark" /></el-form-item>
        <el-form-item label="权限">
          <el-checkbox-group v-model="form.permissions">
            <el-checkbox v-for="item in permissions" :key="item.code" :value="item.code">{{ item.name }}</el-checkbox>
          </el-checkbox-group>
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

const roles = ref<any[]>([]);
const permissions = ref<any[]>([]);
const visible = ref(false);
const form = reactive<any>({ id: 0, code: "", name: "", parent_role_id: null, remark: "", permissions: [], builtin: false });

function nameOf(id: number) {
  return roles.value.find((item) => item.id === id)?.name || "无";
}
async function load() {
  const [roleRes, permRes] = await Promise.all([http.get("/admin/roles"), http.get("/admin/permissions")]);
  roles.value = roleRes.data;
  permissions.value = permRes.data;
}
function openCreate() {
  Object.assign(form, { id: 0, code: "", name: "", parent_role_id: null, remark: "", permissions: [], builtin: false });
  visible.value = true;
}
function openEdit(row: any) {
  Object.assign(form, { ...row, permissions: [...row.permissions] });
  visible.value = true;
}
async function save() {
  if (!form.id) {
    const { data } = await http.post("/admin/roles", form);
    form.id = data.id;
  } else {
    await http.put(`/admin/roles/${form.id}`, form);
  }
  await http.put(`/admin/roles/${form.id}/permissions`, { codes: form.permissions });
  visible.value = false;
  ElMessage.success("角色已保存，下次请求即生效");
  await load();
}
async function remove(row: any) {
  await ElMessageBox.confirm(`删除角色 ${row.name}？`, "确认");
  await http.delete(`/admin/roles/${row.id}`);
  await load();
}
load();
</script>
