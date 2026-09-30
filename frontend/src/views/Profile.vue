<template>
  <div>
    <el-alert v-if="session.user?.must_change_password" title="请先修改初始密码，完成后才能使用其他功能" type="warning" show-icon style="margin-bottom:12px" />
    <el-row :gutter="12">
      <el-col :span="14">
        <el-card header="个人资料">
          <el-form label-width="80px">
            <el-form-item label="用户名"><el-input :model-value="session.user?.username" disabled /></el-form-item>
            <el-form-item label="昵称"><el-input v-model="form.nickname" /></el-form-item>
            <el-form-item label="邮箱"><el-input v-model="form.email" /></el-form-item>
            <el-form-item label="联系方式"><el-input v-model="form.phone" /></el-form-item>
            <el-button type="primary" :disabled="session.user?.must_change_password" @click="save">保存资料</el-button>
          </el-form>
        </el-card>
      </el-col>
      <el-col :span="10">
        <el-card header="头像">
          <el-avatar :size="72" :src="session.user?.avatar_url || ''">{{ session.user?.nickname?.[0] }}</el-avatar>
          <div style="margin-top:12px">
            <el-upload :show-file-list="false" :http-request="upload" accept=".jpg,.jpeg,.png,.webp">
              <el-button :disabled="session.user?.must_change_password">上传头像</el-button>
            </el-upload>
          </div>
        </el-card>
        <el-card header="修改密码" style="margin-top:12px">
          <el-form label-width="80px">
            <el-form-item label="原密码"><el-input v-model="pwd.old_password" type="password" show-password /></el-form-item>
            <el-form-item label="新密码"><el-input v-model="pwd.new_password" type="password" show-password /></el-form-item>
            <el-button type="primary" @click="changePwd">更新密码</el-button>
          </el-form>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive } from "vue";
import { ElMessage } from "element-plus";
import http from "../api/http";
import { useSession } from "../stores/session";

const session = useSession();
const form = reactive({ nickname: "", email: "", phone: "" });
const pwd = reactive({ old_password: "", new_password: "" });

onMounted(() => {
  form.nickname = session.user?.nickname || "";
  form.email = session.user?.email || "";
  form.phone = session.user?.phone || "";
});

async function save() {
  const { data } = await http.put("/profile", form);
  session.user = data;
  ElMessage.success("资料已保存");
}

async function changePwd() {
  const { data } = await http.put("/profile/password", pwd);
  session.setToken(data.token);
  await session.load();
  pwd.old_password = "";
  pwd.new_password = "";
  ElMessage.success("密码已更新");
}

async function upload(option: any) {
  const body = new FormData();
  body.append("file", option.file);
  const { data } = await http.post("/profile/avatar", body);
  session.user = data;
  ElMessage.success("头像已更新");
}
</script>
