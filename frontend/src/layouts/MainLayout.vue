<template>
  <el-container class="shell">
    <el-aside width="220px" class="aside">
      <div class="brand">钓鱼邮件识别</div>
      <el-menu :default-active="route.path" router background-color="#142033" text-color="#d5deea" active-text-color="#8ec5ff">
        <el-menu-item v-for="item in menus" :key="item.path" :index="item.path">{{ item.label }}</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="topbar">
        <span>{{ title }}</span>
        <el-dropdown>
          <span>{{ session.user?.nickname || session.user?.username }}</span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item @click="router.push('/profile')">个人资料</el-dropdown-item>
              <el-dropdown-item @click="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="page"><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useSession } from "../stores/session";

const route = useRoute();
const router = useRouter();
const session = useSession();
const all = [
  { path: "/stats", label: "数据分析", perm: "stats:view" },
  { path: "/detect", label: "邮件识别", perm: "detect:single" },
  { path: "/detect/history", label: "识别记录", perm: "detect:history" },
  { path: "/kg", label: "知识图谱", perm: "kg:view" },
  { path: "/kg/manage", label: "图谱维护", perm: "kg:edit" },
  { path: "/models", label: "模型评估", perm: "model:view" },
  { path: "/admin/datasets", label: "数据集", perm: "dataset:manage" },
  { path: "/admin/train", label: "模型训练", perm: "model:train" },
  { path: "/admin/users", label: "用户管理", perm: "user:manage" },
  { path: "/admin/roles", label: "角色权限", perm: "role:manage" },
];
const menus = computed(() => all.filter((item) => session.has(item.perm)));
const title = computed(() => all.find((item) => item.path === route.path)?.label || "个人资料");

function logout() {
  session.logout();
  router.push("/login");
}
</script>
