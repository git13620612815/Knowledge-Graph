import axios from "axios";
import { ElMessage } from "element-plus";

const http = axios.create({ baseURL: "/api", timeout: 120000 });

http.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

http.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const detail = error.response?.data?.detail;
    const message = typeof detail === "string" ? detail : "请求失败";
    const url = error.config?.url || "";
    if (status === 401 && !url.includes("/auth/login") && !url.includes("/auth/register")) {
      sessionStorage.removeItem("token");
      if (!location.pathname.startsWith("/login")) location.href = "/login";
    }
    if (status !== 401 || url.includes("/auth/login")) ElMessage.error(message);
    return Promise.reject(error);
  }
);

export default http;
