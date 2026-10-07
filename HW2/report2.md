# HW2 — Crafting a Raw IP Packet (ICMP) with Python

**Student ID:** B11302226
**Name:** 黃堉睿 (Yu-Rui Huang)

https://github.com/rayhuang1247/Practice-Of-Communication-network/new/main/HW2

---

## 1. 目標

以 Python raw socket **手工組出一個 IP 封包**（內含 ICMP Echo Request），自行填寫 IP header 與 ICMP header 的每個欄位並計算 checksum，送至另一台主機，並以 Wireshark 驗證封包內容正確。

## 2. 環境

| 角色 | 主機 | IP |
|---|---|---|
| **送封包方**（執行 ip.py） | VM1 | 192.168.56.102 |
| **收封包方**（target） | VM2 | 192.168.56.101 |

- 網段：`192.168.56.0/24`（VirtualBox Host-Only Adapter, `enp0s8`）
- 送出指令：`sudo python3 ip.py` → 輸入 target IP `192.168.56.101`

## 3. Source Code（ip.py）

```python
#!/usr/bin/env python3
import socket
import struct

# ---------- Internet Checksum ----------
def checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

# ---------- 組 ICMP Echo Request ----------
def build_icmp():
    icmp_type, icmp_code = 8, 0      # Type 8 = Echo Request
    icmp_id, icmp_seq = 1, 1
    icmp_data = b'HelloICMP'
    header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    chksum = checksum(header + icmp_data)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, chksum, icmp_id, icmp_seq)
    return header + icmp_data

# ---------- 組 IP header ----------
def build_ip(src_ip, dst_ip, payload):
    ver_ihl = (4 << 4) + 5           # Version 4, IHL 5 (=20 bytes)
    tos, ip_id, frag, ttl = 0, 54321, 0, 64
    proto = socket.IPPROTO_ICMP      # = 1
    tot_len = 20 + len(payload)
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, tot_len, ip_id, frag, ttl, proto, 0, src, dst)
    chksum = checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, tot_len, ip_id, frag, ttl, proto, chksum, src, dst)
    return header

# ---------- 主程式 ----------
def main():
    src_ip = '192.168.56.102'
    dst_ip = input('Enter target IP: ').strip()
    icmp_packet = build_icmp()
    ip_header = build_ip(src_ip, dst_ip, icmp_packet)
    packet = ip_header + icmp_packet

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet, (dst_ip, 0))
    print(f'IP packet sent to {dst_ip}')
    s.close()

if __name__ == '__main__':
    main()
```

### 程式重點

- **checksum()**：Internet Checksum，將資料以 16-bit 為單位相加、進位繞回（one's complement），最後取反。IP header 與 ICMP 各自計算。
- **IP_HDRINCL**：告知 kernel「IP header 由程式自行提供」，避免 kernel 重複加一層 header。
- **兩階段 checksum**：先將 checksum 欄位填 0 組出 header，計算後再填回重組。

## 4. Results

### 4.1 執行與抓包

VM1 執行 `ip.py` 送出封包，VM2 以 tcpdump 抓包存成 `.pcap` 後，於本機 Wireshark 開啟。封包成功送達，且 target 自動回應 Echo Reply，證明手刻封包完全合規（checksum 正確，否則會被丟棄）。

### 4.2 Request（手刻封包）

![request](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW2/figs/reply.png)

### 4.3 Reply（target 回應，佐證封包合規）

![reply](https://github.com/rayhuang1247/Practice-Of-Communication-network/blob/main/HW2/figs/request.png)

### 4.3 欄位驗證

| IP header 欄位 | 程式填入 | Wireshark 顯示 |
|---|---|---|
| Version | 4 | 4 |
| Header Length | 5 (=20 bytes) | 20 bytes |
| Total Length | 20 + 17 = 37 | 37 |
| Identification | 54321 | 54321 |
| Time to Live | 64 | 64 |
| Protocol | ICMP (1) | ICMP (1) |
| Source Address | 192.168.56.102 | 192.168.56.102 |
| Destination Address | 192.168.56.101 | 192.168.56.101 |

ICMP payload `HelloICMP` 亦可於封包 hex 區對應確認。

## 5. 結論

程式正確手工組出 IP + ICMP 封包，每個欄位與 checksum 皆與 Wireshark 解析一致，且 target 回應 Echo Reply，驗證封包完全合規。
