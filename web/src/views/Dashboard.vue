<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";
import { listScans, type ScanListItem } from "../api";
import { t } from "../i18n";
import StatCard from "../components/StatCard.vue";

const router = useRouter();
const scans = ref<ScanListItem[]>([]);
const loaded = ref(false);

async function fetchData() {
  loaded.value = false;
  try {
    const data = await listScans(20);
    scans.value = data;
  } catch {
    scans.value = [];
  }
  loaded.value = true;
}

onMounted(fetchData);

const totalScans = () => scans.value.length;
const totalHigh = () => scans.value.reduce((s, sc) => s + (sc.summary?.critical || 0) + (sc.summary?.high || 0), 0);
const totalFindings = () => scans.value.reduce((s, sc) => s + (sc.summary?.total || 0), 0);
const lastScan = () => {
  if (!scans.value.length) return "—";
  return scans.value[0].created_at.replace("T", " ").slice(0, 16);
};
</script>

<template>
  <section class="hero">
    <h1 class="hero-title">{{ t("dashboard.hero") }}</h1>
    <p class="hero-sub">Rule-driven security baseline scanning for Hyperledger Fabric networks, smart contracts, and Web3 applications.</p>
    <button class="btn btn-primary btn-lg" @click="router.push('/scan/new')">{{ t("dashboard.quickScan") }}</button>
  </section>

  <div class="stats-row">
    <StatCard :value="totalScans()" :label="t('dashboard.totalScans')" />
    <StatCard :value="totalHigh()" :label="t('dashboard.highRisks')" color="#ef4444" />
    <StatCard :value="totalFindings()" :label="t('dashboard.totalFindings')" />
    <StatCard :value="lastScan()" :label="t('dashboard.lastScan')" />
  </div>

  <section v-if="!loaded" class="empty">
    <div class="empty-icon">⏳</div>
    <div class="empty-text">{{ t("common.loading") }}</div>
  </section>

  <template v-else-if="scans.length > 0">
    <div class="section-header">
      <h2>{{ t("dashboard.recentScans") }}</h2>
      <router-link to="/history" class="see-all">View all →</router-link>
    </div>
    <div class="scan-grid">
      <div v-for="s in scans.slice(0, 6)" :key="s.id" class="scan-card card" @click="router.push(`/scan/${s.id}`)">
        <div class="scan-card-top">
          <span class="scan-type-tag">{{ s.target_type }}</span>
          <span class="scan-time">{{ s.created_at.replace("T", " ").slice(5, 16) }}</span>
        </div>
        <div class="scan-card-path">{{ s.target_path }}</div>
        <div class="scan-card-bottom">
          <div class="scan-sevs">
            <span v-if="s.summary.critical" class="sev-dot crit">{{ s.summary.critical }}</span>
            <span v-if="s.summary.high" class="sev-dot high">{{ s.summary.high }}</span>
            <span v-if="s.summary.medium" class="sev-dot med">{{ s.summary.medium }}</span>
            <span v-if="s.summary.low" class="sev-dot low">{{ s.summary.low }}</span>
            <span v-if="s.summary.total === 0" class="sev-clean">Clean</span>
          </div>
          <span class="scan-dur">{{ s.duration.toFixed(1) }}s</span>
        </div>
      </div>
    </div>
  </template>

  <div v-else class="empty">
    <div class="empty-icon">{{ t("dashboard.emptyIcon") }}</div>
    <div class="empty-text">{{ t("dashboard.empty") }}</div>
  </div>
</template>

<style scoped>
.hero {
  text-align: center;
  padding: 3rem 1rem 2.5rem;
}
.hero-title {
  font-size: 2.25rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  margin-bottom: 0.6rem;
  background: linear-gradient(135deg, #e4e4e7 0%, #a1a1aa 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.hero-sub {
  font-size: 0.95rem;
  color: var(--text3);
  max-width: 520px;
  margin: 0 auto 1.5rem;
  line-height: 1.6;
}
.btn-lg {
  padding: 0.7rem 1.6rem;
  font-size: 0.9rem;
}

.stats-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-bottom: 2.5rem;
}
@media (max-width: 768px) {
  .stats-row { grid-template-columns: repeat(2, 1fr); }
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}
.section-header h2 {
  font-size: 1.15rem;
  font-weight: 600;
}
.see-all {
  font-size: 0.85rem;
  color: var(--primary-hover);
}

.scan-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 0.85rem;
}
.scan-card {
  cursor: pointer;
  transition: all 0.2s;
}
.scan-card:hover {
  border-color: var(--primary);
  transform: translateY(-1px);
}
.scan-card-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.scan-type-tag {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--primary-hover);
  background: var(--primary-bg);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}
.scan-time {
  font-size: 0.75rem;
  color: var(--text3);
}
.scan-card-path {
  font-family: "SF Mono", "Fira Code", monospace;
  font-size: 0.78rem;
  color: var(--text2);
  margin-bottom: 0.75rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.scan-card-bottom {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.scan-sevs {
  display: flex;
  gap: 0.4rem;
}
.sev-dot {
  font-size: 0.68rem;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  padding: 0.12rem 0.45rem;
  border-radius: 100px;
}
.sev-dot.crit { background: rgba(239,68,68,0.15); color: #f87171; }
.sev-dot.high { background: rgba(239,68,68,0.08); color: #ef4444; }
.sev-dot.med { background: rgba(245,158,11,0.1); color: #f59e0b; }
.sev-dot.low { background: rgba(99,102,241,0.1); color: #6366f1; }
.sev-clean { font-size: 0.75rem; color: var(--success); font-weight: 500; }
.scan-dur { font-size: 0.75rem; color: var(--text3); }
</style>
