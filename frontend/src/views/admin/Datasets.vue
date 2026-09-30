<template>
  <div>
    <el-card>
      <div class="toolbar">
        <el-button type="primary" @click="importSample">导入内置示例</el-button>
        <el-input v-model="name" placeholder="数据集名称" style="width: 180px" />
        <el-select v-model="label" placeholder="压缩包统一标签" style="width: 160px">
          <el-option label="钓鱼 phish" value="phish" /><el-option label="正常 ham" value="ham" />
        </el-select>
        <el-upload :show-file-list="false" :auto-upload="false" accept=".csv,.zip,.eml,.txt" :on-change="uploadData">
          <el-button>上传数据集</el-button>
        </el-upload>
        <el-upload :show-file-list="false" :auto-upload="false" accept=".csv" :on-change="uploadCert">
          <el-button>导入证书快照</el-button>
        </el-upload>
      </div>
      <el-table :data="datasets">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="sample_count" label="样本数" width="90" />
        <el-table-column prop="phish_count" label="钓鱼" width="80" />
        <el-table-column prop="ham_count" label="正常" width="80" />
        <el-table-column prop="status" label="状态" width="100" />
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column label="操作" width="220">
          <template #default="{ row }">
            <el-button link @click="openSamples(row)">样本</el-button>
            <el-button link @click="clean(row)">清洗</el-button>
            <el-button link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    <el-drawer v-model="drawer" :title="current?.name || '样本'" size="640px">
      <el-table :data="samples" @row-click="openDetail">
        <el-table-column prop="subject" label="主题" />
        <el-table-column prop="label" label="标签" width="90" />
        <el-table-column prop="from_addr" label="发件人" width="180" />
      </el-table>
      <el-pagination layout="prev, pager, next" :total="sampleTotal" :page-size="10" @current-change="loadSamples" />
    </el-drawer>
    <el-dialog v-model="detailVisible" title="样本与三元组" width="760px">
      <p><b>主题：</b>{{ detail.subject }}</p>
      <el-input type="textarea" :rows="6" :model-value="detail.body" readonly />
      <div class="toolbar" style="margin-top:8px">
        <el-select v-model="detail.label" style="width: 140px">
          <el-option label="phish" value="phish" /><el-option label="ham" value="ham" />
        </el-select>
        <el-button @click="saveLabel">保存标签</el-button>
        <el-button type="danger" @click="deleteSample">删除样本</el-button>
        <el-button type="primary" @click="commitSelected">写入选中</el-button>
        <el-button @click="dropSelected">丢弃选中</el-button>
      </div>
      <el-table :data="detail.triples || []" @selection-change="(rows: any[]) => selected = rows">
        <el-table-column type="selection" width="42" />
        <el-table-column prop="head_type" label="头类型" width="110" />
        <el-table-column prop="head" label="头实体" />
        <el-table-column prop="rel" label="关系" width="140" />
        <el-table-column prop="tail" label="尾实体" />
        <el-table-column prop="status" label="状态" width="90" />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import http from "../../api/http";

const datasets = ref<any[]>([]);
const name = ref("上传数据集");
const label = ref("phish");
const drawer = ref(false);
const current = ref<any>(null);
const samples = ref<any[]>([]);
const sampleTotal = ref(0);
const detailVisible = ref(false);
const detail = ref<any>({});
const selected = ref<any[]>([]);

async function load() {
  const { data } = await http.get("/datasets");
  datasets.value = data;
}
async function importSample() {
  await http.post("/datasets/sample");
  ElMessage.success("示例数据已导入");
  await load();
}
async function uploadData(file: any) {
  const body = new FormData();
  body.append("name", name.value || file.name);
  body.append("label", label.value);
  body.append("file", file.raw);
  const { data } = await http.post("/datasets", body);
  if (data.warnings?.length) ElMessage.warning(data.warnings.join("；"));
  else ElMessage.success("数据集已上传");
  await load();
}
async function uploadCert(file: any) {
  const body = new FormData();
  body.append("file", file.raw);
  const { data } = await http.post("/datasets/cert-snapshot", body);
  ElMessage.success(`已导入 ${data.count} 条证书记录`);
}
async function openSamples(row: any) {
  current.value = row;
  drawer.value = true;
  await loadSamples(1);
}
async function loadSamples(page = 1) {
  const { data } = await http.get(`/datasets/${current.value.id}/samples`, { params: { page, size: 10 } });
  samples.value = data.items;
  sampleTotal.value = data.total;
}
async function openDetail(row: any) {
  const { data } = await http.get(`/datasets/${current.value.id}/samples/${row.id}`);
  detail.value = data;
  detailVisible.value = true;
}
async function saveLabel() {
  await http.put(`/datasets/${current.value.id}/samples/${detail.value.id}`, { label: detail.value.label });
  ElMessage.success("标签已更新，原划分已清空");
  await load();
}
async function deleteSample() {
  await http.delete(`/datasets/${current.value.id}/samples/${detail.value.id}`);
  detailVisible.value = false;
  await loadSamples(1);
  await load();
}
async function commitSelected() {
  await http.post(`/datasets/${current.value.id}/triples/commit`, { triple_ids: selected.value.map((item) => item.id) });
  ElMessage.success("三元组已写入图谱");
  await openDetail(detail.value);
}
async function dropSelected() {
  await http.post(`/datasets/${current.value.id}/triples/drop`, { triple_ids: selected.value.map((item) => item.id) });
  ElMessage.success("三元组已丢弃");
  await openDetail(detail.value);
}
async function clean(row: any) {
  await http.post(`/datasets/${row.id}/clean`);
  ElMessage.success("已生成清洗后的新数据集");
  await load();
}
async function remove(row: any) {
  await ElMessageBox.confirm(`删除数据集 ${row.name}？`, "确认");
  const { data } = await http.delete(`/datasets/${row.id}`);
  ElMessage.success(data.mode === "logical" ? "已被训练引用，已改为逻辑删除" : "已删除");
  await load();
}
load();
</script>
