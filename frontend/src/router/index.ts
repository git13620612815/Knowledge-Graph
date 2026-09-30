import { createRouter, createWebHistory } from "vue-router";
import { useSession } from "../stores/session";
import MainLayout from "../layouts/MainLayout.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", component: () => import("../views/Login.vue"), meta: { public: true } },
    { path: "/register", component: () => import("../views/Register.vue"), meta: { public: true } },
    { path: "/forgot", component: () => import("../views/Forgot.vue"), meta: { public: true } },
    {
      path: "/",
      component: MainLayout,
      children: [
        { path: "", redirect: "/stats" },
        { path: "profile", component: () => import("../views/Profile.vue") },
        { path: "stats", component: () => import("../views/Stats.vue"), meta: { perm: "stats:view" } },
        { path: "detect", component: () => import("../views/Detect.vue"), meta: { perm: "detect:single" } },
        { path: "detect/history", component: () => import("../views/History.vue"), meta: { perm: "detect:history" } },
        { path: "kg", component: () => import("../views/KgView.vue"), meta: { perm: "kg:view" } },
        { path: "kg/manage", component: () => import("../views/KgView.vue"), meta: { perm: "kg:edit", manage: true } },
        { path: "models", component: () => import("../views/Models.vue"), meta: { perm: "model:view" } },
        { path: "admin/datasets", component: () => import("../views/admin/Datasets.vue"), meta: { perm: "dataset:manage" } },
        { path: "admin/train", component: () => import("../views/admin/Train.vue"), meta: { perm: "model:train" } },
        { path: "admin/users", component: () => import("../views/admin/Users.vue"), meta: { perm: "user:manage" } },
        { path: "admin/roles", component: () => import("../views/admin/Roles.vue"), meta: { perm: "role:manage" } },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  const session = useSession();
  if (!session.loaded) {
    try {
      await session.load();
    } catch {
      session.logout();
    }
  }
  if (!to.meta.public && !session.token) return "/login";
  if (to.meta.public && session.token) return "/stats";
  if (session.user?.must_change_password && to.path !== "/profile") return "/profile";
  const perm = to.meta.perm as string | undefined;
  if (perm && session.user && !session.has(perm)) return "/profile";
  return true;
});

export default router;
