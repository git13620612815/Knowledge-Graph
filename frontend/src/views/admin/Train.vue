<template>
  <el-card>
    <el-form inline>
      <el-form-item label="数据集">
        <el-select v-model="form.dataset_id" style="width: 220px">
          <el-option v-for="item in datasets" :key="item.id" :label="`${item.name}（${item.sample_count}）`" :value="item.id" />
        </el-select>
      </el-form-item>
      <el-form-item label="轮数"><el-input-number v-model="form.epoch" :min="5" :max="100" /></el-form-item>
      <el-form-item label="批大小"><el-input-number v-model="form.batch_size" :min="8" :max="128" /></el-form-item>
      <el-form-item label="学习率"><el-input-number v-model="form.lr" :min="0.0001" :max="0.01" :step="0.0001" /></el-form-item>
      <el-form-item label="权重衰减"><el-input-number v-model="form.weight_decay" :min="0" :max="0.001" :step="0.0001" /></el-form-item>
      <el-form-item label="Dropout"><el-input-number v-model="form.dropout" :min="0" :max="0.5" :step="0.1" /></el-form-item>
      <el-form-item label="随机种子"><el-input-number v-model="form.seed" /></el-form-item>
      <el-form-item label="早停"><el-switch v-model="form.early_stop" /></el-form-item>
      <el-button type="primary" @click="start">启动训练</el-button>
    </el-form>
    <el-table :data="tasks" style="margin-top: 12px">
      <el-table-column prop="id" label="编号" width="70" />
      <el-table-column prop="dataset_name" label="数据集" />
      <el-table-column prop="status" label="状态" width="140" />
      <el-table-column prop="progress" label="进度" width="80" />
      <el-table-column prop="created_at" label="创建时间" width="170" />
      <el-table-column label="操作" width="240">
        <template #default="{ row }">
          <el-button link @click="openLog(row)">日志</el-button>
          <el-button link @click="cancel(row)">取消</el-button>
          <el-button v-if="row.status === 'SUCCESS'" link type="primary" @click="publish(row)">发布</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-drawer v-model="logVisible" title="训练日志" size="520px">
      <el-input type="textarea" :rows="24" :model-value="logText" readonly />
    </el-drawer>
  </el-card>
</template>

<script setup lang="ts">
import { onBeforeUnmount, reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import http from "../../api/http";

const datasets = ref<any[]>([]);
const tasks = ref<any[]>([]);
const form = reactive({ dataset_id: undefined as number | undefined, epoch: 40, batch_size: 32, lr: 0.001, weight_decay: 0.0001, dropout: 0.3, seed: 42, early_stop: true });
const logVisible = ref(false);
const logText = ref("");
const watching = ref(0);
let timer = 0;

async function load() {
  const [dataRes, taskRes] = await Promise.all([http.get("/datasets"), http.get("/train/tasks")]);
  datasets.value = dataRes.data;
  tasks.value = taskRes.data;
  if (!form.dataset_id && datasets.value.length) form.dataset_id = datasets.value[0].id;
}
async function start() {
  await http.post("/train/tasks", form);
  ElMessage.success("训练任务已进入队列");
  await load();
}
async function openLog(row: any) {
  watching.value = row.id;
  logVisible.value = true;
  await pull();
  window.clearInterval(timer);
  timer = window.setInterval(pull, 3000);
}
async function pull() {
  if (!watching.value) return;
  const { data } = await http.get(`/train/tasks/${watching.value}`);
  logText.value = data.log;
  if (["SUCCESS", "FAILED", "CANCELLED"].includes(data.status)) {
    window.clearInterval(timer);
    await load();
  }
}
async function cancel(row: any) {
  await http.post(`/train/tasks/${row.id}/cancel`);
  ElMessage.success("已发送取消请求");
  await load();
}
async function publish(row: any) {
  const versions = await http.get("/models");
  const exact = versions.data.find((item: any) => item.task_id === row.id);
  if (!exact) return ElMessage.warning("没有找到可发布的版本");
  await http.post(`/models/${exact.id}/publish`);
  ElMessage.success(`已发布 ${exact.version_no}`);
}
onBeforeUnmount(() => window.clearInterval(timer));
load();
</script>
