<template>
  <div>
    <div class="toolbar">
      <el-date-picker v-model="range" type="daterange" value-format="YYYY-MM-DD" start-placeholder="开始日期" end-placeholder="结束日期" />
      <el-select v-model="modelId" clearable placeholder="模型版本" style="width: 220px">
        <el-option v-for="item in models" :key="item.id" :label="item.version_no" :value="item.id" />
      </el-select>
      <el-select v-if="session.has('user:manage')" v-model="userId" clearable placeholder="用户" style="width: 180px">
        <el-option v-for="item in users" :key="item.id" :label="item.username" :value="item.id" />
      </el-select>
      <el-button type="primary" @click="load">筛选</el-button>
      <el-button @click="exportCsv">导出 CSV</el-button>
      <el-button @click="exportPng">导出图表</el-button>
    </div>
    <div class="chart-grid">
      <div ref="trendRef" class="chart-box"></div>
      <div ref="pieRef" class="chart-box"></div>
      <div ref="barRef" class="chart-box"></div>
      <div ref="accRef" class="chart-box"></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import * as echarts from "echarts";
import http from "../api/http";
import { useSession } from "../stores/session";

const session = useSession();
const range = ref<string[]>([]);
const modelId = ref<number | undefined>();
const userId = ref<number | undefined>();
const models = ref<any[]>([]);
const users = ref<any[]>([]);
const trendRef = ref<HTMLElement>();
const pieRef = ref<HTMLElement>();
const barRef = ref<HTMLElement>();
const accRef = ref<HTMLElement>();
const charts: echarts.ECharts[] = [];

function params() {
  return {
    start: range.value?.[0] || "",
    end: range.value?.[1] || "",
    model_id: modelId.value,
    user_id: userId.value,
  };
}

function mount(el: HTMLElement | undefined, option: any) {
  if (!el) return;
  const chart = echarts.init(el);
  chart.setOption(option);
  charts.push(chart);
}

async function load() {
  const { data } = await http.get("/stats/overview", { params: params() });
  charts.splice(0).forEach((item) => item.dispose());
  mount(trendRef.value, {
    title: { text: "识别量趋势", left: 12, top: 8, textStyle: { fontSize: 14 } },
    tooltip: { trigger: "axis" },
    legend: { top: 8, right: 12 },
    xAxis: { type: "category", data: data.trend.map((item: any) => item.date) },
    yAxis: { type: "value" },
    series: [
      { name: "钓鱼", type: "line", data: data.trend.map((item: any) => item.phish), smooth: true },
      { name: "正常", type: "line", data: data.trend.map((item: any) => item.ham), smooth: true },
    ],
  });
  mount(pieRef.value, {
    title: { text: "结果占比", left: 12, top: 8, textStyle: { fontSize: 14 } },
    series: [{
      type: "pie",
      radius: "60%",
      data: [
        { name: "钓鱼", value: data.pie.phish },
        { name: "正常", value: data.pie.ham },
      ],
    }],
  });
  mount(barRef.value, {
    title: { text: "触发特征分布", left: 12, top: 8, textStyle: { fontSize: 14 } },
    xAxis: { type: "category", data: data.features.map((item: any) => item.type) },
    yAxis: { type: "value" },
    series: [{ type: "bar", data: data.features.map((item: any) => item.count) }],
  });
  const empty = data.feedback_accuracy.length === 0;
  mount(accRef.value, empty ? {
    title: { text: "暂无用户反馈，无法计算准确率", left: "center", top: "middle", textStyle: { fontSize: 14, color: "#66758a" } },
  } : {
    title: { text: "反馈准确率", left: 12, top: 8, textStyle: { fontSize: 14 } },
    tooltip: { trigger: "axis" },
    xAxis: { type: "category", data: data.feedback_accuracy.map((item: any) => item.date) },
    yAxis: { type: "value", max: 1 },
    series: [{ type: "line", data: data.feedback_accuracy.map((item: any) => item.accuracy), smooth: true }],
  });
}

async function exportCsv() {
  const response = await http.get("/stats/export", { params: params(), responseType: "blob" });
  const url = URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = "detect-records.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function exportPng() {
  charts.forEach((chart, index) => {
    const link = document.createElement("a");
    link.href = chart.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: "#fff" });
    link.download = `chart-${index + 1}.png`;
    link.click();
  });
}

onMounted(async () => {
  if (session.has("model:view")) {
    const { data } = await http.get("/models");
    models.value = data;
  }
  if (session.has("user:manage")) {
    const { data } = await http.get("/admin/users", { params: { page: 1, size: 100 } });
    users.value = data.items;
  }
  await load();
  window.addEventListener("resize", resize);
});
function resize() { charts.forEach((chart) => chart.resize()); }
onBeforeUnmount(() => {
  window.removeEventListener("resize", resize);
  charts.forEach((chart) => chart.dispose());
});
</script>
