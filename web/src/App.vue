<script setup lang="ts">
import { useRouter } from "vue-router";
import { t, setLang, currentLang } from "./i18n";

const router = useRouter();

function toggleLang() {
  setLang(currentLang.value === "zh" ? "en" : "zh");
}
</script>

<template>
  <div class="shell">
    <header class="topbar">
      <div class="topbar-inner">
        <router-link to="/" class="logo">
          <span class="logo-icon">🛡️</span>
          <span class="logo-text">{{ t("app.title") }}</span>
        </router-link>
        <nav class="nav">
          <router-link to="/" class="nav-link">{{ t("app.dashboard") }}</router-link>
          <router-link to="/scan/new" class="nav-link">{{ t("app.newScan") }}</router-link>
          <router-link to="/history" class="nav-link">{{ t("app.history") }}</router-link>
          <router-link to="/rules" class="nav-link">{{ t("app.rules") }}</router-link>
        </nav>
        <div class="topbar-actions">
          <button class="lang-btn" @click="toggleLang">{{ t("app.lang") }}</button>
          <span class="version">v0.3</span>
        </div>
      </div>
    </header>
    <main class="main">
      <router-view />
    </main>
  </div>
</template>

<style>
*,
*::before,
*::after {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
:root {
  --bg: #0d0d0d;
  --surface: #141414;
  --surface2: #1a1a1a;
  --border: #222;
  --border-hover: #333;
  --text: #e4e4e7;
  --text2: #a1a1aa;
  --text3: #52525b;
  --primary: #6366f1;
  --primary-hover: #818cf8;
  --primary-bg: rgba(99, 102, 241, 0.1);
  --danger: #ef4444;
  --danger-bg: rgba(239, 68, 68, 0.1);
  --warning: #f59e0b;
  --warning-bg: rgba(245, 158, 11, 0.1);
  --success: #10b981;
  --success-bg: rgba(16, 185, 129, 0.1);
  --radius: 10px;
  --radius-sm: 6px;
  --shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.5);
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
html {
  font-size: 15px;
}
body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
a {
  color: var(--text);
  text-decoration: none;
}
a:hover {
  color: var(--primary-hover);
}

/* ---- topbar ---- */
.topbar {
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(13, 13, 13, 0.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
}
.topbar-inner {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  gap: 2rem;
  height: 56px;
  padding: 0 2rem;
}
.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 700;
  font-size: 1rem;
  flex-shrink: 0;
}
.logo-icon {
  font-size: 1.3rem;
}
.logo-text {
  background: linear-gradient(135deg, var(--primary), var(--primary-hover));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.nav {
  display: flex;
  gap: 0.25rem;
  flex: 1;
}
.nav-link {
  padding: 0.4rem 0.85rem;
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text2);
  transition: all 0.15s;
}
.nav-link:hover {
  color: var(--text);
  background: var(--surface2);
}
.nav-link.router-link-active {
  color: var(--text);
  background: var(--surface2);
}
.topbar-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.lang-btn {
  padding: 0.35rem 0.75rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text2);
  font-size: 0.8rem;
  font-family: var(--font);
  cursor: pointer;
  transition: all 0.15s;
}
.lang-btn:hover {
  border-color: var(--border-hover);
  color: var(--text);
}
.version {
  font-size: 0.75rem;
  color: var(--text3);
}

/* ---- main ---- */
.main {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2.5rem 2rem 4rem;
}

/* ---- shared components ---- */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.card:hover {
  border-color: var(--border-hover);
  box-shadow: var(--shadow-md);
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.55rem 1.1rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--surface2);
  color: var(--text);
  font-size: 0.85rem;
  font-weight: 500;
  font-family: var(--font);
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.btn:hover {
  border-color: var(--border-hover);
  background: #252525;
}
.btn-primary {
  background: var(--primary);
  border-color: var(--primary);
  color: #fff;
}
.btn-primary:hover {
  background: var(--primary-hover);
  border-color: var(--primary-hover);
}
.btn-danger {
  border-color: var(--danger);
  color: var(--danger);
  background: transparent;
}
.btn-danger:hover {
  background: var(--danger);
  color: #fff;
}
.btn-sm {
  padding: 0.3rem 0.7rem;
  font-size: 0.8rem;
}

.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.2rem 0.6rem;
  border-radius: 100px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  line-height: 1.4;
}
.badge-critical {
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}
.badge-high {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}
.badge-medium {
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
}
.badge-low {
  background: rgba(99, 102, 241, 0.1);
  color: #6366f1;
}
.badge-info {
  background: rgba(161, 161, 170, 0.1);
  color: #a1a1aa;
}

.form-group {
  margin-bottom: 1.25rem;
}
.form-label {
  display: block;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text2);
  margin-bottom: 0.4rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.form-input,
.form-select {
  width: 100%;
  padding: 0.65rem 0.85rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg);
  color: var(--text);
  font-size: 0.9rem;
  font-family: var(--font);
  transition: border-color 0.15s;
}
.form-input:focus,
.form-select:focus {
  outline: none;
  border-color: var(--primary);
}
.form-hint {
  font-size: 0.78rem;
  color: var(--text3);
  margin-top: 0.35rem;
}

.empty {
  text-align: center;
  padding: 4rem 1rem;
  color: var(--text3);
}
.empty-icon {
  font-size: 2.5rem;
  margin-bottom: 0.75rem;
}
.empty-text {
  font-size: 0.9rem;
}
</style>
