<template>
  <div class="auth-page">
    <section class="auth-intro">
      <h1>找回密码</h1>
      <p>开发环境未开启邮件时，验证码写入 backend/data/logs/mail.log，10 分钟内有效，最多错误 5 次。</p>
    </section>
    <section class="auth-card">
      <div class="panel">
        <h2>重置密码</h2>
        <el-form @submit.prevent="send">
          <el-form-item label="账号"><el-input v-model="account" placeholder="用户名或邮箱" /></el-form-item>
          <el-button @click="send" :loading="sending">发送验证码</el-button>
        </el-form>
        <el-form @submit.prevent="reset" style="margin-top:16px">
          <el-form-item label="验证码"><el-input v-model="code" /></el-form-item>
          <el-form-item label="新密码"><el-input v-model="password" type="password" show-password /></el-form-item>
          <el-button type="primary" style="width:100%" native-type="submit" :loading="loading">重置密码</el-button>
        </el-form>
        <p><router-link to="/login">返回登录</router-link></p>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import http from "../api/http";

const router = useRouter();
const account = ref("");
const code = ref("");
const password = ref("");
const sending = ref(false);
const loading = ref(false);

async function send() {
  sending.value = true;
  try {
    const { data } = await http.post("/auth/forgot", { account: account.value });
    ElMessage.success(data.message);
  } finally {
    sending.value = false;
  }
}

async function reset() {
  loading.value = true;
  try {
    await http.post("/auth/reset", { account: account.value, code: code.value, password: password.value });
    ElMessage.success("密码已重置");
    router.push("/login");
  } finally {
    loading.value = false;
  }
}
</script>
