<template>
  <el-card>
    <div class="legend">
      <span v-for="(color, name) in colors" :key="name"><i class="dot" :style="{ background: color }"></i>{{ labels[name] }}</span>
    </div>
    <div class="toolbar">
      <el-select v-model="types" multiple collapse-tags placeholder="实体类型" style="width: 240px">
        <el-option v-for="(label, name) in labels" :key="name" :label="label" :value="name" />
      </el-select>
      <el-input v-model="keyword" placeholder="名称关键字" style="width: 180px" />
      <el-input-number v-model="minRisk" :min="0" :max="1" :step="0.1" />
      <el-button type="primary" @click="load">查询</el-button>
      <el-button @click="pathVisible = true">路径查询</el-button>
    </div>
    <div v-if="!nodes.length" style="padding: 24px; color: #66758a">当前筛选下没有节点。导入数据并完成训练后，图谱会出现邮件、域名和网址。</div>
    <div ref="box" class="g6-box"></div>
    <el-drawer v-model="drawer" title="节点详情" size="360px">
      <template v-if="current">
        <p>类型：{{ labels[current.type] || current.type }}</p>
        <p>名称：{{ current.name }}</p>
        <p>风险值：{{ current.risk_score }}</p>
        <p>手工标记：{{ current.manual_risk }}</p>
        <p>钓鱼计数 / 正常计数：{{ current.phish_count }} / {{ current.ham_count }}</p>
        <el-form v-if="manage" label-width="80px">
          <el-form-item label="显示名"><el-input v-model="edit.name" /></el-form-item>
          <el-form-item label="备注"><el-input v-model="edit.remark" /></el-form-item>
          <el-form-item label="锁定"><el-switch v-model="edit.locked" /></el-form-item>
          <el-form-item label="风险标记">
            <el-select v-model="edit.manual_risk">
              <el-option label="自动" value="unknown" />
              <el-option label="低" value="low" />
              <el-option label="高" value="high" />
            </el-select>
          </el-form-item>
          <el-button type="primary" @click="saveNode">保存</el-button>
          <el-button type="danger" @click="removeNode(false)">删除</el-button>
          <el-button type="danger" plain @click="removeNode(true)">级联删除</el-button>
        </el-form>
      </template>
    </el-drawer>
    <el-dialog v-model="pathVisible" title="关系路径" width="480px">
      <el-select v-model="fromId" filterable placeholder="起点" style="width: 100%; margin-bottom: 8px">
        <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
      </el-select>
      <el-select v-model="toId" filterable placeholder="终点" style="width: 100%">
        <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
      </el-select>
      <template #footer>
        <el-button type="primary" @click="findPath">查询</el-button>
      </template>
    </el-dialog>
    <el-card v-if="manage" style="margin-top: 12px" header="新增关系 / 合并节点">
      <div class="toolbar">
        <el-select v-model="rel.rel" placeholder="关系" style="width: 160px">
          <el-option v-for="item in rels" :key="item" :label="item" :value="item" />
        </el-select>
        <el-select v-model="rel.source" filterable placeholder="头实体" style="width: 220px">
          <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
        </el-select>
        <el-select v-model="rel.target" filterable placeholder="尾实体" style="width: 220px">
          <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
        </el-select>
        <el-button @click="addRel">添加关系</el-button>
      </div>
      <div class="toolbar">
        <el-select v-model="merge.keep_id" filterable placeholder="保留节点" style="width: 220px">
          <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
        </el-select>
        <el-select v-model="merge.drop_id" filterable placeholder="并入后删除" style="width: 220px">
          <el-option v-for="node in nodes" :key="node.id" :label="node.name" :value="node.id" />
        </el-select>
        <el-button @click="mergeNodes">合并</el-button>
      </div>
    </el-card>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { useRoute } from "vue-router";
import { ElMessage } from "element-plus";
import G6 from "@antv/g6";
import http from "../api/http";

const route = useRoute();
const manage = computed(() => Boolean(route.meta.manage));
const labels: Record<string, string> = {
  Email: "邮件", Url: "URL", Domain: "域名", Ip: "IP", CertIssuer: "证书颁发者", Logo: "Logo", Sender: "发件人", Keyword: "关键词",
};
const colors: Record<string, string> = {
  Email: "#3b6ea5", Url: "#c4533a", Domain: "#d0891d", Ip: "#7a4e9a", CertIssuer: "#2f7d6d", Logo: "#b85c8a", Sender: "#3d7a46", Keyword: "#5c6b7a",
};
const rels = ["CONTAINS_URL", "HOSTED_ON", "RESOLVES_TO", "ISSUED_BY", "HAS_LOGO", "SENT_BY", "REDIRECTS_TO", "MENTIONS", "SIMILAR_LOGO"];
const types = ref<string[]>([]);
const keyword = ref("");
const minRisk = ref<number | undefined>();
const nodes = ref<any[]>([]);
const box = ref<HTMLElement>();
const drawer = ref(false);
const current = ref<any>(null);
const edit = reactive({ name: "", remark: "", locked: false, manual_risk: "unknown" });
const pathVisible = ref(false);
const fromId = ref("");
const toId = ref("");
const rel = reactive({ rel: "HOSTED_ON", source: "", target: "" });
const merge = reactive({ keep_id: "", drop_id: "" });
let graph: any = null;

function short(text: string) {
  return text && text.length > 18 ? text.slice(0, 16) + "…" : text;
}
function toData(payload: any) {
  return {
    nodes: payload.nodes.map((node: any) => ({
      id: node.id,
      label: short(node.name),
      raw: node,
      style: { fill: colors[node.type] || "#5c6b7a" },
    })),
    edges: payload.edges.map((edge: any) => ({
      id: String(edge.id),
      source: edge.source,
      target: edge.target,
      label: edge.rel,
    })),
  };
}
function render(payload: any) {
  nodes.value = payload.nodes;
  if (!box.value) return;
  const data = toData(payload);
  if (!graph) {
    graph = new G6.Graph({
      container: box.value,
      width: box.value.clientWidth,
      height: 640,
      layout: { type: "force", preventOverlap: true, linkDistance: 130 },
      modes: { default: ["drag-canvas", "zoom-canvas", "drag-node"] },
      defaultNode: { size: 28, labelCfg: { position: "bottom", style: { fontSize: 11 } } },
      defaultEdge: { style: { stroke: "#c5d0de" }, labelCfg: { style: { fontSize: 10, fill: "#66758a" } } },
      nodeStateStyles: { highlight: { stroke: "#1f6feb", lineWidth: 3 } },
      edgeStateStyles: { highlight: { stroke: "#1f6feb", lineWidth: 2 } },
    });
    graph.on("node:click", (event: any) => highlight(event.item));
    graph.on("node:dblclick", (event: any) => expand(event.item.getID()));
    graph.data(data);
    graph.render();
  } else {
    graph.changeData(data);
  }
}
function highlight(item: any) {
  graph.getNodes().forEach((node: any) => graph.clearItemStates(node));
  graph.getEdges().forEach((edge: any) => graph.clearItemStates(edge));
  const id = item.getID();
  item.setState("highlight", true);
  graph.getEdges().forEach((edge: any) => {
    const model = edge.getModel();
    if (model.source === id || model.target === id) {
      edge.setState("highlight", true);
      graph.findById(model.source)?.setState("highlight", true);
      graph.findById(model.target)?.setState("highlight", true);
    }
  });
  open(item.getModel().raw);
}
function open(node: any) {
  current.value = node;
  edit.name = node.name;
  edit.remark = node.remark || "";
  edit.locked = Boolean(node.locked);
  edit.manual_risk = node.manual_risk || "unknown";
  drawer.value = true;
}
async function expand(id: string) {
  const { data } = await http.get("/kg/neighbors", { params: { id } });
  const map = new Map(nodes.value.map((node) => [node.id, node]));
  data.nodes.forEach((node: any) => map.set(node.id, node));
  const edges = [...(graph.save().edges || []), ...data.edges];
  const seen = new Set<string>();
  const merged = edges.filter((edge: any) => {
    const key = `${edge.source}-${edge.rel || edge.label}-${edge.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  render({ nodes: [...map.values()], edges: merged.map((edge: any) => ({ id: edge.id, source: edge.source, target: edge.target, rel: edge.rel || edge.label })) });
}
async function load() {
  const { data } = await http.get("/kg/subgraph", {
    params: { types: types.value.join(","), keyword: keyword.value, min_risk: minRisk.value, limit: 150 },
  });
  if (data.truncated) ElMessage.warning("结果已按数量截断，可继续缩小筛选条件");
  render(data);
}
async function findPath() {
  const { data } = await http.get("/kg/path", { params: { from_id: fromId.value, to_id: toId.value, max_hop: 4 } });
  pathVisible.value = false;
  if (!data.nodes?.length) {
    ElMessage.info("4 跳以内没有找到路径");
    return;
  }
  const ids = new Set(data.nodes.map((node: any) => node.id));
  graph.getNodes().forEach((node: any) => node.setState("highlight", ids.has(node.getID())));
  ElMessage.success(data.nodes.map((node: any) => node.name).join(" → "));
}
async function saveNode() {
  const { data } = await http.put("/kg/node", { id: current.value.id, ...edit });
  current.value = data;
  ElMessage.success("节点已更新");
  await load();
}
async function removeNode(cascade: boolean) {
  await http.delete("/kg/node", { params: { id: current.value.id, cascade } });
  drawer.value = false;
  ElMessage.success("节点已删除");
  await load();
}
async function addRel() {
  await http.post("/kg/relations", rel);
  ElMessage.success("关系已添加");
  await load();
}
async function mergeNodes() {
  await http.post("/kg/merge", merge);
  ElMessage.success("节点已合并");
  await load();
}
onMounted(load);
onBeforeUnmount(() => graph?.destroy());
</script>
