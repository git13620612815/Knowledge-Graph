<template>
  <el-card>
    <el-table :data="rows">
      <el-table-column prop="created_at" label="时间" width="170" />
      <el-table-column prop="subject" label="主题" min-width="180" />
      <el-table-column label="预测" width="90">
        <template #default="{ row }">{{ row.pred_label === "phish" ? "钓鱼" : "正常" }}</template>
      </el-table-column>
      <el-table-column prop="confidence" label="置信度" width="90" />
      <el-table-column prop="model_version" label="模型" width="150" />
      <el-table-column label="反馈" width="160">
        <template #default="{ row }">
          <el-select :model-value="row.feedback" placeholder="标记" style="width: 120px" @change="(value: string) => mark(row, value)">
            <el-option label="钓鱼" value="phish" />
            <el-option label="正常" value="ham" />
          </el-select>
        </template>
      </el-table-column>
      <el-table-column type="expand">
        <template #default="{ row }">
          <div v-for="item in row.evidences" :key="item.path_text">{{ item.path_text }}</div>
          <div v-if="!row.evidences?.length">无图谱证据</div>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination layout="prev, pager, next" :total="total" :page-size="10" style="margin-top:12px" @current-change="load" />
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import http from "../api/http";

const rows = ref<any[]>([]);
const total = ref(0);

async function load(page = 1) {
  const { data } = await http.get("/detect/records", { params: { page, size: 10 } });
  rows.value = data.items;
  total.value = data.total;
}
async function mark(row: any, feedback: string) {
  await http.put(`/detect/records/${row.id}/feedback`, { feedback });
  row.feedback = feedback;
  ElMessage.success("反馈已保存");
}
onMounted(() => load(1));
</script>
