<template>
  <div class="auth-page">
    <section class="auth-intro"><h1>创建普通用户</h1><p>新注册账号只能使用识别、图谱查看和统计功能。管理权限由管理员分配。</p></section>
    <section class="auth-card">
      <div class="panel">
        <h2>注册</h2>
        <el-form @submit.prevent="submit">
          <el-form-item label="用户名"><el-input v-model="form.username" /></el-form-item>
          <el-form-item label="邮箱"><el-input v-model="form.email" /></el-form-item>
          <el-form-item label="密码"><el-input v-model="form.password" type="password" show-password /></el-form-item>
          <el-form-item label="确认密码"><el-input v-model="form.confirm_password" type="password" show-password /></el-form-item>
          <el-button type="primary" style="width:100%" native-type="submit" :loading="loading">注册</el-button>
        </el-form>
        <p><router-link to="/login">返回登录</router-link></p>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import http from "../api/http";

const router = useRouter();
const loading = ref(false);
const form = reactive({ username: "", email: "", password: "", confirm_password: "" });

async function submit() {
  loading.value = true;
  try {
    await http.post("/auth/register", form);
    ElMessage.success("注册成功，请登录");
    router.push("/login");
  } finally {
    loading.value = false;
  }
}
</script>
