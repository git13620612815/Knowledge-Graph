<template>
  <div class="login">
    <section class="stage">
      <svg class="mesh" viewBox="0 0 720 640" aria-hidden="true">
        <defs>
          <linearGradient id="line" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#8ec5ff" stop-opacity="0.15" />
            <stop offset="1" stop-color="#8ec5ff" stop-opacity="0.7" />
          </linearGradient>
        </defs>
        <g class="edges" stroke="url(#line)" fill="none">
          <path d="M168 188 C250 150, 300 150, 372 168" />
          <path d="M410 190 C470 210, 500 250, 528 292" />
          <path d="M190 230 C210 300, 200 360, 188 412" />
          <path d="M230 430 C310 450, 390 470, 470 456" />
          <path d="M390 196 C360 280, 300 340, 214 400" />
          <path d="M548 320 C560 380, 540 420, 506 450" />
        </g>
        <g class="nodes" fill="#d7e8ff">
          <g transform="translate(168 188)">
            <circle r="7" /><text y="28">邮件</text>
          </g>
          <g transform="translate(390 168)">
            <circle r="6" /><text y="26">网址</text>
          </g>
          <g transform="translate(548 304)">
            <circle r="7" /><text y="28">域名</text>
          </g>
          <g transform="translate(176 430)">
            <circle r="6" /><text y="26">发件人</text>
          </g>
          <g transform="translate(492 468)">
            <circle r="6" /><text y="26">证书</text>
          </g>
        </g>
      </svg>
      <div class="stage-copy">
        <div class="brand">
          <span class="mark">图谱</span>
          <span>知识图谱 · 图神经网络</span>
        </div>
        <h1>钓鱼邮件识别系统</h1>
        <p>从邮件中抽出网址、域名、证书颁发者和发件人，连成可查询的图谱，再给出钓鱼判定和置信度。</p>
        <ul>
          <li>单封识别与批量识别</li>
          <li>图谱路径与风险分数</li>
          <li>模型训练与版本发布</li>
        </ul>
      </div>
    </section>
    <section class="pane">
      <form class="card" @submit.prevent="submit">
        <h2>登录</h2>
        <p class="lead">使用用户名或邮箱进入系统</p>
        <label>
          <span>账号</span>
          <el-input v-model="form.account" size="large" placeholder="用户名或邮箱" autocomplete="username" />
        </label>
        <label>
          <span>密码</span>
          <el-input v-model="form.password" size="large" type="password" show-password placeholder="请输入密码" autocomplete="current-password" />
        </label>
        <el-button class="enter" type="primary" size="large" native-type="submit" :loading="loading">进入系统</el-button>
        <div class="links">
          <router-link to="/register">注册账号</router-link>
          <router-link to="/forgot">忘记密码</router-link>
        </div>
      </form>
    </section>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import http from "../api/http";
import { useSession } from "../stores/session";

const router = useRouter();
const session = useSession();
const loading = ref(false);
const form = reactive({ account: "", password: "" });

async function submit() {
  if (!form.account.trim() || !form.password) {
    ElMessage.warning("请填写账号和密码");
    return;
  }
  loading.value = true;
  try {
    const { data } = await http.post("/auth/login", form);
    session.setToken(data.token);
    session.user = data.user;
    session.loaded = true;
    router.push(data.user.must_change_password ? "/profile" : "/stats");
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.login {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  background: #0c1524;
}
.stage {
  position: relative;
  overflow: hidden;
  display: flex;
  align-items: center;
  color: #e7eef8;
  padding: 72px 64px;
  background:
    radial-gradient(520px 320px at 18% 18%, rgba(61, 139, 253, 0.28), transparent 70%),
    radial-gradient(420px 280px at 78% 82%, rgba(32, 84, 160, 0.35), transparent 72%),
    #0c1524;
}
.mesh {
  position: absolute;
  inset: 40px 0 auto auto;
  width: min(720px, 100%);
  height: auto;
  opacity: 0.9;
  pointer-events: none;
}
.edges path {
  stroke-width: 1.4;
}
.nodes text {
  fill: #b7cbe4;
  font-size: 13px;
  text-anchor: middle;
}
.stage-copy {
  position: relative;
  z-index: 1;
  max-width: 460px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  color: #9fb4cc;
  font-size: 14px;
  letter-spacing: 0.4px;
}
.mark {
  display: inline-grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: #1f6feb;
  color: white;
  font-size: 13px;
  font-weight: 700;
}
h1 {
  margin: 22px 0 12px;
  font-size: 44px;
  line-height: 1.2;
  font-weight: 680;
}
.stage-copy p {
  margin: 0;
  color: #c5d4e6;
  line-height: 1.75;
  font-size: 15px;
}
.stage-copy ul {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
  margin: 28px 0 0;
  padding: 0;
  list-style: none;
}
.stage-copy li {
  padding: 6px 12px;
  border: 1px solid rgba(184, 208, 234, 0.28);
  border-radius: 999px;
  color: #d5e4f5;
  font-size: 14px;
  line-height: 1.4;
  white-space: nowrap;
  background: rgba(255, 255, 255, 0.04);
}
.pane {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 24px;
  background: #f3f6fb;
}
.card {
  width: min(400px, 100%);
  padding: 36px 32px 28px;
  border-radius: 18px;
  background: white;
  box-shadow: 0 18px 50px rgba(16, 32, 51, 0.08);
}
h2 {
  margin: 0;
  font-size: 28px;
  font-weight: 680;
}
.lead {
  margin: 8px 0 22px;
  color: #66758a;
  font-size: 14px;
}
label {
  display: block;
  margin-bottom: 16px;
}
label span {
  display: block;
  margin-bottom: 8px;
  color: #314055;
  font-size: 13px;
  font-weight: 600;
}
.enter {
  width: 100%;
  margin-top: 6px;
}
.links {
  display: flex;
  justify-content: space-between;
  margin-top: 18px;
  font-size: 14px;
}
@media (max-width: 900px) {
  .login { grid-template-columns: 1fr; }
  .stage { padding: 36px 24px 28px; }
  .mesh { display: none; }
  .stage-copy { margin-top: 0; }
  h1 { font-size: 32px; }
  .stage-copy li { white-space: normal; }
}
</style>
