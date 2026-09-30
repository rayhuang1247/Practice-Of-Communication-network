# Week 03 Homework — Network-Layer DoS Attack Simulation

**Student ID:** B11302226
**Name:** 黃堉睿
**Date:** 2026-09-30
**檔案位置:** https://github.com/rayhuang1247/Practice-Of-Communication-network/tree/main/HW/HW1
---

## 0. Environment Overview（共用環境）

本次所有模擬皆在**完全隔離的 host-only 虛擬網路**中進行，不接觸任何校園或公用網路，符合作業之 Strict Network & Scope Policy。攻擊方與目標方皆為本人所有之虛擬機，並在報告中具名。

### Network Topology

| 角色 | 主機名 | IP Address | OS |
|---|---|---|---|
| **Attacker** | vm1-llm-server | 192.168.56.102 | Ubuntu (CLI, no GUI) |
| **Target** | vm2-client | 192.168.56.101 | Ubuntu (CLI, no GUI) |

- Network segment: `192.168.56.0/24`（VirtualBox Host-Only Adapter, `enp0s8`）
- 兩台 VM 之間可互通（已用 `ping` 驗證），並透過 host-only 模式與外部網路隔離，攻擊流量不會外洩。
- Hypervisor: Oracle VirtualBox。

### Tools Used

| 工具 | 用途 |
|---|---|
| `hping3` | 產生高速 ICMP / TCP SYN 封包（攻擊一、三） |
| `Scapy` (python3) | 手工構造畸形分片封包（攻擊二 Ping of Death） |
| `tcpdump` | target 端封包捕捉，驗證攻擊流量特徵 |
| `top` / `ss` / `watch` | target 端即時監控 CPU、半開連線 |
| `tmux` | 於 CLI 環境分割終端，同時觀察多項指標 |

---

# Attack 1: ICMP Ping Flooding

## 1. Setup

**原理**：高速送出大量 ICMP Echo Request，target 每收一個封包就觸發中斷，CPU 全耗在 softirq 處理封包，無法服務正常行程 → DoS。

**指令**：
```bash
# Target (192.168.56.101) 監控
top
sudo tcpdump -p -i any icmp -n
# Attacker (192.168.56.102) 發動
sudo hping3 --icmp --flood 192.168.56.101
```

## 2. Screenshots

**Figure 1 — Baseline**（CPU idle 99.7%，ping RTT 1.67 ms）https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_1_Baseline.png

![Figure 1 - Baseline](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_1_Baseline.png)

**Figure 2 — Under attack**（CPU idle 掉到 12.7%、si 44.4%，tcpdump 封包狂刷）https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_2_ICMP_Under_Attack.png

![Figure 2 - Under attack](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_2_ICMP_Under_Attack.png)

**Figure 3 — hping3 統計**（送出 1,900,522 封包）

無截圖

**Figure 4 — Recovery**（攻擊停止後 idle 回 99.7%）https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_4_Recovery.png

![Figure 4 - Recovery](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_4_Recovery.png)

## 3. Analysis

| 指標 | Baseline | Under Attack |
|---|---|---|
| CPU idle | 99.7% | 12.7% |
| softirq (si) | ~0% | 44.4% |
| load avg (1m) | 0.00 | 1.63 |

CPU 幾乎被封包中斷處理耗盡（si + sy ≈ 86%），`ksoftirqd` 浮上 CPU 排行，證實過載來自封包中斷而非使用者程式。攻擊規模達 190 萬封包。

**防禦**：ICMP rate limiting（`iptables ... --limit 1/s`）、防火牆丟棄異常來源、必要時關閉 ICMP echo 回應。

---

# Attack 2: Ping of Death (PoD)

## 1. Setup

**原理**：送出多個分片，讓它們**重組後總長 > 65,535 bytes**（IP 合法上限）。老舊系統重組時緩衝區溢位 → 當機。

**指令**（Attacker 用 Scapy 送 65,500 bytes payload，自動分片）：
```bash
# Target (192.168.56.101) 抓分片
sudo tcpdump -p -i any -n 'host 192.168.56.101 and (icmp or ip[6:2] & 0x3fff != 0)' -v
# Attacker (192.168.56.102) 發動
sudo python3
>>> from scapy.all import *
>>> pkt = IP(dst='192.168.56.101')/ICMP()/('X'*65500)
>>> for i in range(5): send(pkt, verbose=0)
```

## 2. Screenshots

**Figure 5 — tcpdump 抓到分片**（同一 id 63424，offset 遞增至 65120，末片 offset 65120 + len 408 = 65528 > 65535）https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_5_PoD_Fragments.png

![Figure 5 - PoD fragments](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_5_PoD_Fragments.png)

## 3. Analysis

分片重組後總長超過 IP 上限，構成畸形封包。但 **target 未當機、資源正常**。

**發現**：現代 Linux kernel 的 IP reassembly 內建**邊界檢查**，偵測到重組後超長即直接丟棄分片，不進行重組 → 免疫於 PoD。

**Why 分片而非單一大封包**：乙太網 MTU 僅 1500 bytes，實體上無法一次送出 65,536 bytes，故必須拆成合法小片、讓 offset 累加至爆表——每片單獨合法，合起來才致命。

**防禦**：kernel 早已內建修補；另可用防火牆檢查 fragment offset、限制重組總長。

---

# Attack 3: SYN Flood

## 1. Setup

**原理**：大量送出 TCP **SYN** 但不回最後 ACK，target 為每個半開連線佔用 backlog 佇列並等 timeout，佇列塞滿後無法接受正常連線 → DoS。

**指令**：
```bash
# Target (192.168.56.101) 開靶服務 + 監控
sudo python3 -m http.server 80
watch -n 1 'ss -tan state syn-recv | wc -l'
# Attacker (192.168.56.102) 發動
sudo hping3 -S --flood -p 80 192.168.56.101
```

## 2. 雙輪對照（本攻擊亮點）

### Round 1 — 防禦開啟（預設）

SYN cookies = 1。攻擊進行中，attacker `curl http://192.168.56.101:80` 仍回 **HTTP 200**，服務存活。

**Figure 6 — curl 成功取得完整 HTML**https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_6_SYN_Round1_Alive.png

![Figure 6 - Round 1 service alive](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_6_SYN_Round1_Alive.png)

### Round 2 — 關閉防禦

```bash
sudo sysctl -w net.ipv4.tcp_syncookies=0
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=64
```

再攻擊（送出 >1700 萬 SYN），target 出現 **soft lockup**、多核心卡死、`systemd-logind`/`networkd` watchdog timeout、連 ollama 服務都停擺、OOM 警告 → **系統級癱瘓，DoS 成立**。

**Figure 7 — target kernel log**（soft lockup - CPU stuck、watchdog timeout）https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_7_SYN_Round2_Lockup.png

![Figure 7 - Round 2 soft lockup](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW/HW1/fig/Figure_7_SYN_Round2_Lockup.png)

> 實驗後已復原：`tcp_syncookies=1`、backlog 128（重開機還原）。

## 3. Analysis

| | Round 1（cookies 開） | Round 2（cookies 關） |
|---|---|---|
| 服務 | 正常回 200 | 系統癱瘓 |
| 結果 | 防禦有效 | DoS 成立 |

SYN cookies 在佇列將滿時不再為新 SYN 佔資源，改以加密 cookie 編碼連線，佇列不被塞爆。此對照證明**防禦機制的有無決定攻擊成敗**。

**Why 難防**：每個 SYN 都是合法封包，與正常連線的 SYN 無異，伺服器收到當下無法分辨攻擊或真客戶——這是需 SYN cookies 這類機制的原因。

**防禦**：啟用 SYN cookies、加大 backlog、防火牆限制單一來源 SYN 速率、對偽造來源以 uRPF 過濾。

---

# Conclusion

| 攻擊 | 結果 | 關鍵原因 |
|---|---|---|
| ICMP Flood | **成功** | 中斷處理無上限，量大即癱 |
| Ping of Death | 被防禦 | kernel reassembly 邊界檢查 |
| SYN Flood | 防禦有效 / 關閉後**癱瘓** | SYN cookies 存亡關鍵 |

**核心心得**：volumetric 攻擊（ICMP Flood）因封包本身合法、難以根治，至今仍是難題；exploit 型攻擊（PoD）可由 kernel 一勞永逸修補；SYN Flood 則證明**防禦組態的必要性**——同一攻擊在有無防禦下結果天差地別。
