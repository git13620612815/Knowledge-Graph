<template>
  <el-card>
    <el-tabs v-model="tab">
      <el-tab-pane label="单封识别" name="single">
        <el-upload drag :auto-upload="false" :limit="1" accept=".eml,.txt" :on-change="onSingle">
          <div>拖入或选择一封 .eml / .txt 邮件</div>
        </el-upload>
        <el-button type="primary" style="margin-top:12px" :loading="loading" @click="detectSingle">开始识别</el-button>
      </el-tab-pane>
      <el-tab-pane label="批量识别" name="batch">
        <el-upload drag :auto-upload="false" :limit="1" accept=".zip,.csv" :on-change="onBatch">
          <div>上传 zip 或 csv，单次最多 200 封</div>
        </el-upload>
        <el-button type="primary" style="margin-top:12px" :loading="loading" @click="detectBatch">提交批量任务</el-button>
        <el-progress v-if="progress.total" :percentage="percent" style="margin-top:12px" />
      </el-tab-pane>
    </el-tabs>
    <el-table v-if="records.length" :data="records" style="margin-top:16px" row-key="id">
      <el-table-column prop="subject" label="主题" min-width="180" />
      <el-table-column label="结果" width="90">
        <template #default="{ row }">{{ row.pred_label === "phish" ? "钓鱼" : "正常" }}</template>
      </el-table-column>
      <el-table-column prop="confidence" label="置信度" width="100" />
      <el-table-column prop="p_gnn" label="模型分" width="100" />
      <el-table-column prop="p_rule" label="图谱分" width="100" />
      <el-table-column prop="model_version" label="模型版本" width="160" />
      <el-table-column type="expand">
        <template #default="{ row }">
          <div v-if="!row.evidences?.length">没有命中已有高风险节点。</div>
          <div v-for="item in row.evidences" :key="item.path_text">{{ item.entity_type }} {{ item.risk_score }}：{{ item.path_text }}</div>
          <div style="margin-top:8px">实体：{{ (row.summary || []).map((item: any) => item.type + ":" + item.name).join("；") }}</div>
          <el-button v-if="session.has('kg:edit')" size="small" style="margin-top:8px" @click="commit(row)">写入图谱</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import http from "../api/http";
import { useSession } from "../stores/session";

const session = useSession();
const tab = ref("single");
const loading = ref(false);
const single = ref<File | null>(null);
const batch = ref<File | null>(null);
const records = ref<any[]>([]);
const progress = ref({ done: 0, total: 0 });
const percent = computed(() => progress.value.total ? Math.round(progress.value.done / progress.value.total * 100) : 0);

function onSingle(file: any) { single.value = file.raw; }
function onBatch(file: any) { batch.value = file.raw; }

async function detectSingle() {
  if (!single.value) return ElMessage.warning("请先选择邮件");
  loading.value = true;
  try {
    const body = new FormData();
    body.append("file", single.value);
    const { data } = await http.post("/detect/single", body);
    records.value = [data];
  } finally {
    loading.value = false;
  }
}

async function detectBatch() {
  if (!batch.value) return ElMessage.warning("请先选择文件");
  loading.value = true;
  try {
    const body = new FormData();
    body.append("file", batch.value);
    const { data } = await http.post("/detect/batch", body);
    await poll(data.task_id);
  } finally {
    loading.value = false;
  }
}

async function poll(id: number) {
  for (let i = 0; i < 120; i++) {
    const { data } = await http.get(`/detect/tasks/${id}`);
    progress.value = { done: data.done_count, total: data.total_count };
    if (data.status === "SUCCESS") {
      records.value = data.records;
      return;
    }
    if (data.status === "FAILED") throw new Error(data.error_message || "批量识别失败");
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function commit(row: any) {
  await http.post(`/detect/records/${row.id}/commit-graph`);
  ElMessage.success("已写入知识图谱");
}
</script>
