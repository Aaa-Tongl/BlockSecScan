<p align="center">
  <br>
  <samp><a href="#english">English</a> · <a href="#中文">中文</a></samp>
  <br><br>
</p>

<h1 align="center">🛡️ BlockSecScan</h1>

<p align="center">
  <b>Multi-platform Blockchain Security Scanner</b><br>
  <sub>Fabric · Smart Contracts · RPC · Web3 · AI-Ready</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/version-0.5.0-orange" alt="Version">
  <img src="https://img.shields.io/badge/tests-90%20passed-green" alt="Tests">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Fabric-Config_Security-green">
  <img src="https://img.shields.io/badge/Fabric-Runtime_Security-green">
  <img src="https://img.shields.io/badge/Smart_Contract-Slither-blue">
  <img src="https://img.shields.io/badge/RPC-Endpoint_Security-red">
  <img src="https://img.shields.io/badge/Web3-Frontend_Scan-purple">
</p>

<br>

> ⚠️ **Disclaimer**: This tool is for **authorized security testing, educational purposes, and self-owned asset inspection only**. Do not scan targets without explicit authorization. Users are responsible for any legal consequences arising from improper use.

<br>

---

# English

## Overview

BlockSecScan is a rule-driven, multi-platform blockchain security scanner. It detects misconfigurations and vulnerabilities across Hyperledger Fabric, Solidity smart contracts, RPC endpoints, and Web3 frontends.

## Quick Start

```bash
pip install -e ".[dev]"

# Scan Fabric config files
blocksec scan fabric-config --path ./my-fabric-project

# Scan running Fabric containers
blocksec scan fabric-runtime --local

# Scan Smart Contracts (requires Slither + solc)
pip install -e ".[contract]"
blocksec scan contract --path ./my-hardhat-project

# Scan RPC endpoint
blocksec scan rpc --target http://127.0.0.1:8545

# Scan Web3 frontend
blocksec scan web3 --path ./my-dapp

# Export reports
blocksec scan fabric-config --path . --format html --output report.html
blocksec scan fabric-config --path . --format sarif --output blocksec.sarif

# Web GUI
uvicorn blocksec.web.server:app --port 8000
cd web && npm install && npm run dev
```

## Scan Targets

| Command | Target | Detects |
|---------|--------|---------|
| `scan fabric-config` | Fabric project directory | TLS, CouchDB, Docker, secrets, certificates, policies |
| `scan fabric-runtime` | Running Docker containers | Root containers, exposed ports, TLS, CouchDB access |
| `scan contract` | Solidity/Hardhat project | Reentrancy, access control, tx.origin, arithmetic, OWASP SWC mapping |
| `scan rpc` | Ethereum JSON-RPC endpoint | Exposed namespaces, CORS, TLS, client version |
| `scan web3` | Web3 frontend source | Private keys, mnemonics, RPC keys, unlimited approvals, CSP |

## Report Formats

JSON · Markdown · HTML · SARIF (GitHub Code Scanning)

## Architecture

```
Models → RuleEngine → Scanners(6) → CoreEngine → Public API → CLI / Web GUI
```

6 scanners: `FabricConfig` · `FabricRuntime` · `SmartContract` · `Rpc` · `Web3`

## Project Structure

```
blocksec/
├── api/            # Public API
├── cli/            # Typer CLI
├── core/           # Engine + Registry
├── models/         # Pydantic v2 models
├── rule_engine/    # YAML rules + matching
├── reports/        # JSON/MD/HTML/SARIF export
├── rules/          # 13 Fabric rules + RPC/Web3 rules
├── scanners/       # 5 scanner plugins
│   ├── fabric_config/
│   ├── fabric_runtime/
│   ├── smart_contract/
│   ├── rpc/
│   └── web3/
├── utils/          # Certificate parsing
├── web/            # FastAPI backend
├── config/         # Settings

web/                # Vue 3 frontend (i18n EN/ZH)
labs/               # 13 lab targets
tests/              # 90 tests
```

## Tests

```bash
pytest                    # 90 passed
ruff check blocksec/ tests/  # All checks passed
```

## License

[Apache-2.0](LICENSE)

<br>

---

# 中文

## 概述

BlockSecScan 是一个规则驱动的多平台区块链安全扫描工具，覆盖 Hyperledger Fabric 配置/运行时、Solidity 智能合约、RPC 端点、Web3 前端。

## 快速开始

```bash
pip install -e ".[dev]"

# 扫描 Fabric 配置文件
blocksec scan fabric-config --path ./my-fabric-project

# 扫描运行中的 Fabric 容器
blocksec scan fabric-runtime --local

# 扫描智能合约 (需要 Slither + solc)
pip install -e ".[contract]"
blocksec scan contract --path ./my-hardhat-project

# 扫描 RPC 端点
blocksec scan rpc --target http://127.0.0.1:8545

# 扫描 Web3 前端
blocksec scan web3 --path ./my-dapp

# 导出报告
blocksec scan fabric-config --path . --format html --output report.html
blocksec scan fabric-config --path . --format sarif --output blocksec.sarif

# Web GUI
uvicorn blocksec.web.server:app --port 8000
cd web && npm install && npm run dev
```

## 扫描类型

| 命令 | 目标 | 检测内容 |
|---------|--------|---------|
| `scan fabric-config` | Fabric 项目目录 | TLS、CouchDB、Docker、密钥、证书、策略 |
| `scan fabric-runtime` | 运行中的 Docker 容器 | root运行、端口暴露、TLS、CouchDB可达 |
| `scan contract` | Solidity/Hardhat 项目 | 重入、权限控制、tx.origin、OWASP SWC 映射 |
| `scan rpc` | 以太坊 JSON-RPC 端点 | 危险namespace暴露、CORS、TLS、版本泄露 |
| `scan web3` | Web3 前端源码 | 私钥泄露、助记词、RPC Key、无限授权、CSP |

## 报告格式

JSON · Markdown · HTML · SARIF (GitHub Code Scanning)

## 架构

```
Models → RuleEngine → Scanners(6个) → CoreEngine → Public API → CLI / Web GUI
```

6 个扫描器：FabricConfig · FabricRuntime · SmartContract · Rpc · Web3

## 开源协议

[Apache-2.0](LICENSE)

<br>

<p align="center"><sub>Made by <a href="https://github.com/Aaa-Tongl">Aaa-Tong</a></sub></p>
