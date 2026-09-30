import { defineStore } from "pinia";
import http from "../api/http";

export const useSession = defineStore("session", {
  state: () => ({
    token: sessionStorage.getItem("token") || "",
    user: null as any,
    loaded: false,
  }),
  actions: {
    has(code: string) {
      return Boolean(this.user?.permissions?.includes(code));
    },
    async load() {
      if (!this.token) {
        this.user = null;
        this.loaded = true;
        return;
      }
      const { data } = await http.get("/auth/me");
      this.user = data;
      this.loaded = true;
    },
    setToken(token: string) {
      this.token = token;
      sessionStorage.setItem("token", token);
    },
    logout() {
      this.token = "";
      this.user = null;
      sessionStorage.removeItem("token");
    },
  },
});
