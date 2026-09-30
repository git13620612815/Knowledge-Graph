<template>
  <div>
    <div class="toolbar">
      <el-select v-model="leftId" placeholder="模型版本" style="width: 240px" @change="draw">
        <el-option v-for="item in models" :key="item.id" :label="labelOf(item)" :value="item.id" />
      </el-select>
      <el-select v-model="rightId" clearable placeholder="对比版本" style="width: 240px" @change="draw">
        <el-option v-for="item in models" :key="item.id" :label="labelOf(item)" :value="item.id" />
      </el-select>
    </div>
    <el-alert v-if="warning" :title="warning" type="warning" show-icon style="margin-bottom:12px" />
    <div class="card-grid" v-if="current">
      <div class="metric" v-for="item in cards" :key="item.key">
        <span>{{ item.name }}</span>
        <strong>{{ show(current.metrics?.[item.key]) }}</strong>
        <small v-if="other">对比 {{ show(other.metrics?.[item.key]) }}</small>
      </div>
    </div>
    <div class="chart-grid" v-show="current">
      <div ref="matrixRef" class="chart-box"></div>
      <div ref="rocRef" class="chart-box"></div>
    </div>
    <el-empty v-if="!models.length" description="还没有训练完成的模型版本" />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import * as echarts from "echarts";
import http from "../api/http";
import { useSession } from "../stores/session";

const session = useSession();
const models = ref<any[]>([]);
const leftId = ref<number>();
const rightId = ref<number>();
const warning = ref("");
const matrixRef = ref<HTMLElement>();
const rocRef = ref<HTMLElement>();
let matrix: echarts.ECharts | null = null;
let roc: echarts.ECharts | null = null;
const current = computed(() => models.value.find((item) => item.id === leftId.value));
const other = computed(() => models.value.find((item) => item.id === rightId.value));
const cards = [
  { key: "accuracy", name: "准确率" },
  { key: "precision", name: "精确率" },
  { key: "recall", name: "召回率" },
  { key: "f1", name: "F1" },
];

function labelOf(item: any) {
  return `${item.version_no}${item.published ? "（已发布）" : ""}`;
}
function show(value: any) {
  return value === null || value === undefined ? "无法计算" : value;
}

async function draw() {
  warning.value = "";
  if (leftId.value && rightId.value && session.has("model:compare")) {
    const { data } = await http.get("/models/compare", { params: { left: leftId.value, right: rightId.value } });
    warning.value = data.message;
  }
  await nextTick();
  const metrics = current.value?.metrics;
  if (!metrics || !matrixRef.value || !rocRef.value) return;
  matrix ||= echarts.init(matrixRef.value);
  roc ||= echarts.init(rocRef.value);
  const cm = metrics.confusion_matrix || [[0, 0], [0, 0]];
  const heat = [
    [0, 0, cm[0][0]], [1, 0, cm[0][1]], [0, 1, cm[1][0]], [1, 1, cm[1][1]],
  ];
  matrix.setOption({
    title: { text: "混淆矩阵", left: 12, textStyle: { fontSize: 14 } },
    tooltip: {},
    xAxis: { type: "category", data: ["预测正常", "预测钓鱼"] },
    yAxis: { type: "category", data: ["实际正常", "实际钓鱼"] },
    visualMap: { min: 0, max: Math.max(...heat.map((item) => item[2] as number), 1), show: false },
    series: [{ type: "heatmap", data: heat, label: { show: true } }],
  });
  const fpr = metrics.roc?.fpr || [];
  const tpr = metrics.roc?.tpr || [];
  roc.setOption({
    title: { text: metrics.auc === null ? "AUC 无法计算" : `ROC  AUC ${metrics.auc}`, left: 12, textStyle: { fontSize: 14 } },
    tooltip: { trigger: "axis" },
    xAxis: { type: "value", name: "FPR", min: 0, max: 1 },
    yAxis: { type: "value", name: "TPR", min: 0, max: 1 },
    series: [{ type: "line", data: fpr.map((value: number, index: number) => [value, tpr[index]]), showSymbol: false }],
  });
}

onMounted(async () => {
  const { data } = await http.get("/models");
  models.value = data;
  leftId.value = data.find((item: any) => item.published)?.id || data[0]?.id;
  await draw();
  window.addEventListener("resize", resize);
});
function resize() { matrix?.resize(); roc?.resize(); }
onBeforeUnmount(() => {
  window.removeEventListener("resize", resize);
  matrix?.dispose();
  roc?.dispose();
});
</script>
