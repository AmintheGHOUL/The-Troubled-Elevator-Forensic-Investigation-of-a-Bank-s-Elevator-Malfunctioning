# DFRWS 2023 — The Troubled Elevator: Complete Solution Write-Up

**Challenge:** DFRWS 2023 — The Troubled Elevator  
**Source:** https://github.com/dfrws/dfrws2023-challenge  
**Domain:** ICS/SCADA Forensics — PLC Memory, Network Traffic, Desktop Memory  
**Author:** VCU SAFE Lab (Security and Forensics Engineering Laboratory)  
**Tools:** Wireshark/tshark, Volatility 3, binwalk, 7-Zip, Python 3, cmp/xxd/strings

---

## Important Limitations

Before reading, note the key evidential boundaries of this analysis:

- **Employee-01 host artifacts unavailable.** No memory dump or disk image of DESKTOP-RSRBUGJ (192.168.10.164) was provided. All conclusions about that machine are derived from network traffic only.
- **CCTV clock synchronization.** The CCTV footage was correlated to PCAP timestamps manually by aligning observable events with confirmed upload times. No embedded timecode was verified against a reference clock. Phase-level alignment is high confidence; second-level alignment is approximate.
- **Desktop memory predates the attack by one week.** The CEO memory dump is from June 22; the attack occurred June 29. It cannot prove the CEO machine was clean on the day of the attack — only that it was clean when imaged.
- **Deleted rung content not recovered.** The diff shows a `RungMetadata` element was removed but this XML element stores only metadata — not the actual contact/coil logic. The safety interlock conclusion is inferred from context, not read directly from the rung body.
- **SAME_CALL causality not fully traced.** The variable removal is documented in the diff. The exact rungs that referenced it were not traced because the `RungMetadata` XML does not expose individual contact/coil detail.
- **Offset-to-I/O mapping.** The claim that offset 0x5D419 maps to output coil states is supported by M221 Programming Guide documentation and behavioral correlation. A complete memory map from the engineering project would make this definitive.

---

## Solution Mind Map

<p align="center">
  <img src="visuals/troubled_elevator_solution_mindmap.svg" alt="DFRWS 2023 Troubled Elevator Solution Mind Map" width="900">
</p>

The mind map below shows the complete solution structure — four artifact branches converging on the central conclusion. Each branch corresponds to one artifact type, and each leaf is a key finding from that artifact.

| Branch | Artifact | Key findings |
|---|---|---|
| Blue | Network capture (PCAP) | 3 devices→PLC, 4 uploads, attacker ID, UMAS FC90 |
| Teal | PLC memory (ExtRAM/OnChipRAM) | ZIP extraction, 4 code changes, diff confirms uploads, final 4 bytes |
| Coral | Desktop memory | Victim confirmed, browser activity, USB artifact, no code injection |
| Amber | CCTV footage | 7 phases, physical corroboration, clock synchronization note |

---

## Table of Contents

1. [Evidence Inventory](#1-evidence-inventory)
2. [Understanding the Network and Elevator Manual](#2-understanding-the-network-and-elevator-manual)
3. [CCTV Footage Analysis](#3-cctv-footage-analysis)
4. [Network Traffic Analysis — PCAP](#4-network-traffic-analysis--pcap)
5. [PLC Memory Analysis](#5-plc-memory-analysis)
6. [Desktop Memory Forensics](#6-desktop-memory-forensics)
7. [Key References and How We Used Them](#7-key-references-and-how-we-used-them)
8. [Alternative Hypotheses Considered](#8-alternative-hypotheses-considered)
9. [MITRE ATT&CK for ICS Mapping](#9-mitre-attck-for-ics-mapping)
10. [ICS Threat Response and Human Impact Q&A](#10-ics-threat-response-and-human-impact-qa)
11. [Complete Attack Timeline](#11-complete-attack-timeline)
12. [Conclusions](#12-conclusions)

---

## 1. Evidence Inventory

All artifacts were verified by SHA256 before analysis.

| # | Filename | Type | SHA256 |
|---|---|---|---|
| 1 | 142728_162728.pcapng | Network capture (14:27–16:27) | 3b42d8ec...e1ef885c9 |
| 2 | DESKTOP-JKS05LO-20230622-143255.raw | CEO desktop memory dump | c476d6be...8dbc22c0f |
| 3 | ExtRAM_20230629143509.bin | PLC ExtRAM snapshot #1 (14:35) | ee0b4e0d...346093a46 |
| 4 | ExtRAM_20230629145014–160538.bin ×6 | PLC ExtRAM snapshots #2–7 | Verified |
| 5 | OnChipRAM_20230629143506–160514.bin ×7 | PLC OnChipRAM snapshots | Verified |
| 6 | Crop_fit.mp4 | CCTV elevator footage | a036e615...be78b5d |
| 7 | Elevator Manual.pdf | Schneider M221 reference | 083bf2f8...b8583c266 |
| 8 | Network Diagrams.pdf | OT network topology | e674c32e...b41bbc9 |

---

## 2. Understanding the Network and Elevator Manual

### 2.1 Reading the Network Diagram

Before touching any artifact, the provided `Network Diagrams.pdf` establishes the intended network topology and defines which devices should — and should not — communicate with the PLC. Any deviation from this baseline in the PCAP is evidence.

The diagram reveals a **flat Layer-2 architecture** — every device on the same `192.168.10.x` subnet with no VLAN segmentation and no firewall between employee workstations and the PLC. This is the structural vulnerability that made the attack possible. In a properly segmented Purdue Model network, employee workstations at Levels 4–5 would have no direct visibility to PLC devices at Level 0–1.

**Devices from the network diagram:**

| Device | IP | Role | Expected PLC Access |
|---|---|---|---|
| PLC (M221CE16R) | 192.168.10.45 | Elevator controller | N/A (target) |
| HMI | 192.168.10.121 | Operator interface | Yes — polling |
| Engineering WS | 192.168.10.130 | PLC programming station | Yes — maintenance only |
| Employee-01 (DESKTOP-RSRBUGJ) | 192.168.10.164 | Regular workstation | **NO** |
| Employee-02 | 192.168.10.242 | Regular workstation | No |
| Employee-03 | 192.168.10.101 | Regular workstation | No |
| CEO Desktop (DESKTOP-JKS05LO) | 192.168.133.137 | Corporate VM | No (different subnet) |

> **Key takeaway:** The network diagram is your threat model baseline. Any device deviating from its expected communication pattern is a suspect.

### 2.2 Reading the Elevator Manual

The `Elevator Manual.pdf` and the Modicon M221 Programming Guide document the PLC controlling the elevator. Three areas must be understood before analyzing any artifact:

**Physical I/O mapping** — every bit has a physical meaning:

| Address | Symbol | Physical Component |
|---|---|---|
| %I0.0 | LS1 | Limit Switch Floor 1 |
| %I0.1 | LS2 | Limit Switch Floor 2 |
| %I0.2 | LS3 | Limit Switch Floor 3 |
| %I0.3 | LDR_CLOSE | Door Limit Close sensor |
| %I0.8 | LDR_OPEN | Door Limit Open sensor |
| %I0.5–0.7 | ECB1–3 | External Call Buttons 1–3 |
| %Q0.0 | DOOR_OPEN | Door open motor control output |
| %Q0.1 | DOOR_CLOSE | Door close motor control output |

**Memory architecture (from M221 Programming Guide):**
- **ExtRAM (512KB):** Stores the uploaded EcoStruxure project as a ZIP-compressed XML archive, plus the I/O image table and runtime data
- **OnChipRAM (128KB):** Stores the running control logic execution state, firmware configuration, timer and counter values, and system variables

**Communication protocol:** The M221 uses UMAS (Unified Messaging Application Services) over Modbus TCP Function Code 90 (0x5A) — Schneider's proprietary protocol used by EcoStruxure Machine Expert for programming, monitoring, and configuration.

> **Regarding authentication:** In this challenge environment, the PLC accepted UMAS engineering commands from Employee-01 without any observed authentication challenge. This is consistent with known Schneider UMAS security weaknesses (see CVE-2020-28212) and the importance of enabling Application Password protection. The specific behavior varies by firmware version and configuration — see Section 7 for detail.

### 2.3 Full Network Inventory (Discovered During PCAP Analysis)

PCAP analysis revealed 17 devices on the OT network — 10 more than the network diagram showed. At least 5 sent Schneider EcoStruxure discovery traffic (UDP port 27127), yet only one communicated with the PLC as an unauthorized engineering client:

| IP | Identity | Schneider Protocol? | Talked to PLC? |
|---|---|---|---|
| 192.168.10.1 | Schneider gateway/switch | Yes — port 27127 responder | No |
| 192.168.10.45 | M221 PLC | N/A | Target |
| 192.168.10.104 | Unknown workstation | Yes — port 1743 | No |
| 192.168.10.110 | Unknown workstation | Yes — port 27127 | No |
| 192.168.10.121 | HMI | Yes | Yes (legitimate) |
| 192.168.10.130 | Engineering WS (logger) | Yes | Yes (legitimate) |
| 192.168.10.153 | VM_PLC (SAFE Lab test VM) | Yes — port 27127 | No |
| **192.168.10.164** | **DESKTOP-RSRBUGJ (Employee-01)** | **Yes** | **YES — unauthorized** |
| 192.168.10.241 | DHCP server (Schneider switch) | Yes — port 27126 | No |
| Others (109, 112, 119, 125, 138, 242) | Various workstations/devices | No | No |

Multiple machines had Schneider software but only Employee-01 sent unauthorized uploads. This is relevant context, though it does not by itself prove who was at the keyboard.

---

## 3. CCTV Footage Analysis

### 3.1 Clock Synchronization Note

The CCTV footage (`Crop_fit.mp4`) was correlated to PCAP timestamps manually by aligning observable events (elevator movement, door behavior) with upload events confirmed in the network capture. No verified embedded timecode was extracted from the video. Phase-level synchronization is reliable; claims that specific events occurred "within seconds" of specific PCAP timestamps are approximate.

### 3.2 Pre-Incident Phase

An employee uses the elevator normally — travelling to floor 3 and returning to floor 1. The elevator functions correctly. This establishes a visual baseline for normal behavior and confirms the system was operating before the first upload at 14:27:51.

### 3.3 Entry Phase — Kristi Wayne

Kristi Wayne enters at floor 1 and presses a floor button. This is the trigger for upload #3 at approximately 15:25:05. The attacker was monitoring the PLC's floor call flags (F1CALL/F2CALL/F3CALL) at 2 reads/second via EcoStruxure's live variable monitor. Network evidence shows these flags transitioned from 0x00 (no calls) to 0x01 (call active) between the 14:50 and 15:35 snapshots, corroborating that a floor button was pressed.

### 3.4 Phase 1 — Elevator Stuck Between Floors 2 and 3

The elevator travels upward then stops mid-floor. This is consistent with the removal of the `SAME_CALL` variable. Based on its name ("SameFloorCall") and comment, this variable handled same-floor call deduplication — likely preventing the elevator from re-responding to a call for the floor it currently occupies. Its removal likely disrupted floor-call state transitions.

> **Limitation:** The precise causality requires tracing every rung that referenced `SAME_CALL` in the baseline program. The `RungMetadata` XML does not expose contact/coil detail directly.

### 3.5 Phase 2 — Doors Open During Movement

The elevator descends and the doors begin opening while still moving. This is consistent with the deleted rung from the "Elevator Door" subtask. The diff confirmed one `RungMetadata` block was removed, meaning one rung of door-control logic was eliminated. The CCTV behavior is consistent with a door-control interlock being affected, but the exact logic of the deleted rung cannot be proven from the `RungMetadata` diff alone — that element stores metadata, not contacts or coils.

### 3.6 Phase 3 — Abnormal Door Cycling

Erratic rapid door behavior is observed. The timer was modified from `Preset=10, Base=OneSecond` (10 seconds) to `Preset=5000, Base=OneMilliSeconds` (5000 ms = 5 seconds). The delay approximately halved and the base unit changed. The CCTV shows abnormal cycling consistent with altered door timing. Note that the timer math gives approximately 5 seconds — "sub-second cycling" is not supported by this change alone and would require additional evidence from CCTV frame timing or runtime timer values.

### 3.7 Phase 4 — Doors Sealed

The elevator returns to floor 1 and the doors do not open. Upload #4 at 15:46:48 delivered the final program. The last ExtRAM snapshot (16:05) shows bits 0 and 1 at offset 0x5D419 clearing from 0x8B to 0x88, alongside a door lock flag at 0x5D440 transitioning from 0x00 to 0x01. The clearing of the output coil bits means both door motor outputs were de-energized. The doors may remain sealed because of their mechanical state, elevator brake behavior, or the lock flag — the combination of de-energized outputs and lock flag change is consistent with the CCTV observation.

### 3.8 Rescue

Emergency responders extract Ms. Wayne. The attacker disconnected at 15:47:05.

### 3.9 CCTV Phase Summary

| Phase | CCTV Observation | Code Change | Confidence |
|---|---|---|---|
| Pre-incident | Normal operation | None | High |
| Entry | Kristi enters, presses floor button | Upload #3 triggered | High (PCAP corroborated) |
| Phase 1 | Stuck between floors 2–3 | SAME_CALL removed | Medium (causality inferred) |
| Phase 2 | Doors open during movement | RungMetadata removed from door-control logic | Medium (contact/coil content not recovered) |
| Phase 3 | Abnormal door cycling | Timer: 10s → 5s | High (timer math confirmed) |
| Phase 4 | Doors sealed at floor 1 | Upload #4 + lock flag | High (I/O state corroborated) |
| Rescue | Emergency services | N/A | High |

---

## 4. Network Traffic Analysis — PCAP

### 4.1 Protocol Distribution

```bash
# Total packet count and protocol breakdown
tshark -r 142728_162728.pcapng -q -z io,phs

# Count Modbus packets
tshark -r 142728_162728.pcapng \
  -Y "mbtcp" \
  -T fields -e ip.src | wc -l
```

The capture contains 208,335 total packets. 123,479 (59%) are Modbus TCP. All PLC-bound Modbus traffic uses **Function Code 90 (0x5A)** — the UMAS identifier. Standard Modbus function codes are 1–127; FC90 is Schneider-proprietary.

> Any host sending FC90/UMAS traffic is acting as a Schneider engineering or monitoring client. In this case, the discovery pattern and upload sequence are consistent with EcoStruxure Machine Expert behavior specifically, though any Schneider UMAS client could technically generate FC90 traffic.

### 4.2 Who Talked to the PLC?

```bash
tshark -r 142728_162728.pcapng \
  -Y "ip.dst == 192.168.10.45" \
  -T fields -e ip.src \
  | sort | uniq -c | sort -rn
```

```
67681  192.168.10.121   HMI (expected — legitimate polling)
40058  192.168.10.130   Engineering WS (expected — logger)
 1755  192.168.10.164   Employee-01 (UNAUTHORIZED)
```

Three devices talked to the PLC. Two match the network diagram. One does not.

### 4.3 Engineering WS — Legitimate SCADA Logger

The Engineering WS sends exactly 2,782 packets/minute (46.4 reads/second) — a constant machine-generated rhythm. Its startup at 14:34:59 performs a sequential memory scan stepping 0xEC bytes at a time, reading 0x07EC bytes per request — consistent with a SCADA historian polling all PLC state at 46 Hz. No upload commands (0x41/0x42) were ever observed from this host. It is a monitoring system, not an attacker.

```bash
# Engineering WS per-minute packet count
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.130 and mbtcp" \
  -T fields -e frame.time \
  | awk '{print substr($1,1,16)}' \
  | sort | uniq -c
```

The per-minute breakdown reveals distinct operational phases:

| Time window | Packets/min | Assessment |
|---|---|---|
| 14:27 | 5 | Brief startup — logger initializing |
| 14:34 | 342 | Ramp-up — sequential memory scan begins |
| 14:35 | 2,440 | Full operation — spike as logger catches up |
| 14:50–15:50 | 2,782 | Steady state — exactly 46.4 reads/second |
| 15:55 | 157 | Brief pause |
| 15:56–16:04 | ~413 | Reduced polling resumes |
| 16:05 | 3,195 | Bulk export spike — 15-minute cycle |
| 16:20 | 3,195 | Second bulk export spike (confirms interval) |

The 16:05 and 16:20 spikes are exactly 15 minutes apart — matching the PLC memory snapshot interval. These correlate with the snapshot acquisition process interacting with the logger.

**PLC response states from the logger:** At 14:35, every logger response from the PLC contains all-zero bytes — `00feec00 0000000000...` (254 bytes of zeros). This is consistent with the PLC restarting after the first malicious upload. By 14:50, the PLC returns rich active data including timer values, coil states, and counter values, confirming the malicious program is fully executing. The logger therefore captured the entire attack from first upload through rescue, providing an independent record of PLC state at 46 reads/second throughout.

### 4.4 Attack Timeline — Per-Minute Analysis

```bash
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and mbtcp" \
  -T fields -e frame.time \
  | awk '{print substr($1,1,16)}' \
  | sort | uniq -c
```

Four burst windows are visible against a background of low-rate monitoring:

| Time | Packets | Event |
|---|---|---|
| 14:27 | 549 | Upload #1 — ZIP header PK\x03\x04 detected in payload |
| 15:00 | 265 | Upload #2 |
| 15:25 | 193 | Upload #3 — triggered when Kristi entered elevator |
| 15:46 | 141 | Upload #4 — final program |

Between bursts: 4–8 packets/min = EcoStruxure live variable monitoring at ~2 reads/second.

### 4.5 Confirming Each Upload — EndDownload Command

Every successful UMAS program upload ends with EndDownload (0x42 0x00):

```bash
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and mbtcp" \
  -T fields -e frame.time -e modbus.data \
  | grep "00420000"
```

```
14:27:53.867  00420000   Upload #1 confirmed
15:00:25.629  00420000   Upload #2 confirmed
15:25:06.514  00420000   Upload #3 confirmed — 1.251 seconds total transfer
15:46:50.110  00420000   Upload #4 confirmed
```

**Upload #3 — millisecond-precise reconstruction:**

```bash
# Isolate the full upload #3 sequence
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and mbtcp" \
  -T fields -e frame.time -e modbus.data \
  | grep "T15:25:0[3-6]" | grep -E "f441|f480|f481|4200"
```

```
15:25:03.763  f441ff00       StartDownload — PLC told to expect new program
15:25:04.851  f480           BeginFileTransfer — transfer channel opened
15:25:05.263  f429...        ZIP data begins (first write block)
15:25:05.445  f481 00000000  Compressed malicious program payload
15:25:06.514  00420000       EndDownload — program committed to PLC
```

Total transfer time: **1.251 seconds** (15:25:05.263 → 15:25:06.514). The ZIP payload in the data blocks contains the malicious `entry` XML with `attaxk` comment and the SAME_CALL removal — the exact changes confirmed by the ExtRAM program extraction.

### 4.6 The UMAS Upload Protocol — Decoded

The full four-step upload sequence:

```
f441ff00    StartDownload (0x41)      — prepare PLC for new program
f480        BeginFileTransfer (0x80)  — open transfer channel
f4xxxx...   FileTransfer blocks       — send compressed ZIP data
00420000    EndDownload (0x42)        — commit program to PLC
```

This matches the UMAS protocol documentation from the Kaspersky ICS-CERT paper (see Section 7).

### 4.7 Attacker Machine Identification

```bash
# Hostname from NetBIOS/LLMNR
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and nbns" \
  -T fields -e nbns.name | head -5

# MAC address from ARP
tshark -r 142728_162728.pcapng \
  -Y "arp.src.proto_ipv4 == 192.168.10.164" \
  -T fields -e arp.src.hw_mac | head -3
```

```
Hostname:    DESKTOP-RSRBUGJ
MAC:         00:0c:29:5a:da:a3
OUI prefix:  00:0c:29 = VMware — virtual machine
```

### 4.8 Network Evidence Regarding Employee-01 Compromise Status

```bash
# Any incoming control commands to Employee-01?
tshark -r 142728_162728.pcapng \
  -Y "ip.dst == 192.168.10.164" \
  -T fields -e ip.src -e _ws.col.Protocol \
  | grep -v "192.168.10.45" | sort -u

# Any external connections?
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 or ip.dst == 192.168.10.164" \
  -T fields -e ip.src -e ip.dst \
  | grep -v "192.168.10" | sort -u
```

**PCAP findings:**
- Zero incoming control commands from any host during the capture window
- Zero connections outside the 192.168.10.x subnet
- Non-PLC traffic is limited to standard Windows broadcasts (NBNS, LLMNR, SSDP) and EcoStruxure device discovery (UDP port 27127)

**The EcoStruxure discovery finding:** At 14:27:36 — 9 seconds before the first PLC connection — Employee-01 broadcast a 37-byte UDP packet to port 27127. Multiple devices responded including the PLC at 192.168.10.45. The discovery payload (`baf35b2f7e03757d6f0f29533327c637726d...`) is Schneider's proprietary discovery protocol — a fixed 18-byte header followed by a device-specific encoded payload. The PLC, gateway (192.168.10.1), VM_PLC (192.168.10.153), and two unknown workstations (192.168.10.110, 192.168.10.104) all responded. This is self-initiated behavior matching the EcoStruxure "Discover Devices" UI action.

**The 20 QueryGetComInfo sessions — four clusters:**

```bash
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and mbtcp" \
  -T fields -e frame.time -e modbus.data \
  | grep "00720100"
```

Employee-01 issued 20 QueryGetComInfo (0x7201) commands in 4 tight clusters — one per upload:

| Cluster | Timestamps | Pattern |
|---|---|---|
| 1 (Upload #1) | 14:27:45, 14:28:03 ×3, 14:28:26, 14:29:15 | Single → triple retry burst → stabilize |
| 2 (Upload #2) | 15:00:17, 15:00:43 ×3, 15:00:48 | Single → triple retry burst → stabilize |
| 3 (Upload #3) | 15:24:59, 15:25:16 ×3, 15:25:20 | Single → triple retry burst → stabilize |
| 4 (Upload #4) | 15:46:41, 15:47:00 ×3, 15:47:03 | Single → triple retry burst → stabilize |

Each cluster follows an identical pattern: a single connection attempt, then a triple rapid-retry burst at millisecond intervals (EcoStruxure's documented automatic retry when the M221 responds slowly), then a stable session. This is software-specific behavior that would only appear if a human was operating EcoStruxure Machine Expert and the software itself was managing the retry logic.

**Complete UMAS command profile:**

```bash
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.164 and mbtcp" \
  -T fields -e modbus.data \
  | cut -c1-8 | sort | uniq -c | sort -rn
```

| Command | Code | Count | Purpose |
|---|---|---|---|
| Read variable block | 0x240a02 | 571 | Live monitoring — watching elevator I/O |
| Keepalive ping | 0x0004 | 223 | Session heartbeat |
| Read variable block (small) | 0x240702 | 187 | Smaller batch reads |
| Read single variable | 0x240102 | 103 | Individual variable reads |
| Session acknowledgement | 0x0002 | 36 | Protocol handshake |
| QueryGetComInfo | 0x720100 | 20 | Session initialization — 4 clusters |
| EndDownload | 0x420000 | 4 | Confirmed 4 program uploads |
| StartDownload | 0x41ff00 | 1 | Upload initiation |

The 861 read requests (571+187+103) against 4 EndDownloads illustrates the ratio of surveillance to action — the attacker spent the vast majority of the session watching the elevator state and waiting.

> **Assessment:** The PCAP contains no evidence of remote control of Employee-01 during the capture window. The traffic pattern — self-initiated discovery, consistent EcoStruxure session retry behavior, human-paced monitoring at 2 reads/second, uploads timed to physical events — is more consistent with local interactive use than with externally controlled malware. However, without host memory or disk evidence from Employee-01 (no image was provided), remote compromise cannot be completely ruled out. The strongest defensible conclusion is machine-level attribution to DESKTOP-RSRBUGJ / 192.168.10.164, with local interactive use as the best-supported hypothesis.

### 4.9 Attacker Surveillance — Watching for Kristi

Between uploads, Employee-01 polled specific variable indices at 2 reads/second. The UMAS read commands targeted floor call flags (F1CALL, F2CALL, F3CALL) and door sensor states — the values needed to determine when Kristi entered. Upload #3 began within approximately 5 seconds of the floor call flags becoming active, consistent with a human operator watching a live variable display and triggering the upload manually.

### 4.10 PLC Physical State Reconstructed from Network Data

The Engineering WS logger responses allow the PLC's physical output state to be reconstructed directly from network traffic, without relying on the memory snapshots. By comparing PLC responses to the logger at 14:50 (first malicious program active) versus 15:35 (Kristi trapped, fourth upload approaching), specific byte-level changes are visible:

```bash
# Extract PLC responses to the logger at two key windows
tshark -r 142728_162728.pcapng \
  -Y "ip.src == 192.168.10.45 and ip.dst == 192.168.10.130 and mbtcp" \
  -T fields -e frame.time -e modbus.data \
  | grep "T14:50:01\|T15:35:05" | head -6
```

Comparing the first rich-data response packet at 14:50 against the equivalent packet at 15:35:

| Offset | 14:50 value | 15:35 value | Interpretation |
|---|---|---|---|
| 0x0014 | 0x10 | 0x50 | PLC mode register — operating state changed |
| 0x0097 | 0x00 | 0x01 | Floor call flag SET — Kristi pressed a floor button |
| 0x009F | 0x00 | 0x01 | Second floor call flag SET |
| 0x00BC–0xC0 | 181/206/179 | 177/198/175 | Execution time counters — program cycle times |
| 0x009E (pkt2) | 0x761c (7,196) | 0xC308 (49,928) | PLC scan cycle counter — +42,732 cycles in 45 min |

The flags at offsets 0x0097 and 0x009F transitioning from 0x00 to 0x01 provide network-level evidence that a floor button was pressed during the attack window. This independently corroborates the CCTV observation of Kristi pressing the floor button — derived purely from the logger's routine polling responses, not from any dedicated forensic collection.

### 4.11 Other Devices — Complete OT Network Picture

PCAP analysis reveals 17 devices on the network versus the 7 in the network diagram. The additional devices do not show PLC attack behavior, but their identification is relevant to understanding the full network exposure:

```bash
# All source IPs observed
tshark -r 142728_162728.pcapng \
  -T fields -e ip.src | sort -u | grep "192.168.10"
```

| IP | Identification | Evidence |
|---|---|---|
| 192.168.10.1 | Schneider gateway/switch | Responds to port 27127 discovery with 194-byte Schneider payload |
| 192.168.10.104 | Unknown workstation | SSDP M-SEARCH + UDP port 1743 (EcoStruxure communication port) |
| 192.168.10.109 | Mobile device | Two mDNS sleep-proxy packets only — phone or tablet in power-save |
| 192.168.10.110 | Unknown workstation | WS-Discovery XML on port 3702 + port 27127 EcoStruxure discovery |
| 192.168.10.112 | Network printer | mDNS IPP/IPPS/SMB printer queries |
| 192.168.10.119 | DHCP relay/server | Issues DHCP Offer and ACK responses |
| 192.168.10.125 | Unknown workstation | SSDP + WPAD proxy search (looking for proxy autoconfiguration) |
| 192.168.10.138 | Unknown workstation | DHCP Inform — recently joined the network |
| 192.168.10.153 | VM_PLC (SAFE Lab test VM) | Announces itself as "VM_PLC" via BROWSER protocol; sends port 27127 discovery; has Adobe software (ARMMF.ADOBE.COM NBNS queries) |
| 192.168.10.241 | DHCP server (Schneider switch) | Issues DHCP NAK responses; sends port 27126 Schneider management traffic |

**DHCP NAK events:** The DHCP server (192.168.10.241) issued NAK responses to the Engineering WS (192.168.10.130) at 15:01:57 and to an unknown workstation (192.168.10.138) at 15:26:08 — immediately after uploads #2 and #3. This is consistent with the PLC restarting during program uploads causing connected devices to lose network synchronization and attempt DHCP lease renewal.

**Employee-02 boot sequence:** At exactly 14:35:55 — 8 minutes after the first attack upload — Employee-02 (192.168.10.242) performed a full Windows network stack initialization sequence:

```
14:35:55  IGMPv3  Leave group 224.0.0.251 (mDNS)
14:35:55  IGMPv3  Leave group 224.0.0.252 (LLMNR)
14:35:55  IGMPv3  Join group 224.0.0.251
14:35:55  IGMPv3  Join group 239.255.255.250 (SSDP)
14:35:55  MDNS    Query: DESKTOP-RSRBUGJ.local  ← looking up attacker's hostname
14:35:55  LLMNR   Query: DESKTOP-RSRBUGJ        ← second lookup of attacker
14:35:55  NBNS    Registration: DESKTOP-RSRBUGJ
14:35:57  DNS     Query: www.msftconnecttest.com ← Windows connectivity check (no DNS server on OT network)
```

This is the exact sequence of a Windows machine booting up. Employee-02 turned on their computer and Windows' automatic name resolution queried for DESKTOP-RSRBUGJ — the attacker's machine — almost immediately. The DNS queries for `www.msftconnecttest.com` and `dns.msftncsi.com` went unanswered (no DNS server on the OT network, generating ICMP port unreachable responses from Employee-03 at 192.168.10.101). Employee-02 is a witness, not a participant — they booted up during the attack but show no PLC communication of any kind.

---

## 5. PLC Memory Analysis

### 5.1 Why Volatility Cannot Be Used Here

Volatility is built around OS memory structures — page tables, kernel objects, process lists. The M221 runs bare-metal firmware with no OS, no virtual memory, and no process structures. There is nothing for Volatility to parse. PLC memory forensics requires: `cmp`, `xxd`, `strings`, `binwalk`, and Python.

### 5.2 ExtRAM Differential Analysis

```bash
cd 'PLC Memory Dumps'

for pair in '143509 145014' '145014 150519' '150519 152024' \
            '152024 153528' '153528 155033' '155033 160538'; do
  a=$(echo $pair | cut -d' ' -f1)
  b=$(echo $pair | cut -d' ' -f2)
  count=$(cmp -l ExtRAM_20230629${a}.bin ExtRAM_20230629${b}.bin | wc -l)
  echo "$a -> $b: $count bytes changed"
done
```

```
143509 → 145014:     15 bytes   minimal — first upload settling
145014 → 150519:  7,317 bytes   LARGE — malicious program active
150519 → 152024:     18 bytes   near-static — elevator idle
152024 → 153528:  7,287 bytes   LARGE — attack active (Kristi enters)
153528 → 155033:  6,324 bytes   LARGE — final program installed
155033 → 160538:      4 bytes   near-static — post-incident
```

Large changes correlate precisely with the upload windows identified in the PCAP.

### 5.3 Finding the Program Archive — binwalk

```bash
for f in ExtRAM_*.bin; do
  echo "=== $f ==="
  binwalk $f | grep -iE "zip|end of zip"
done
```

All seven dumps contain a ZIP archive starting at **offset 0xD00B** (53,259 decimal). End offsets vary because the compressed program changes size with each upload.

### 5.4 Extracting the ZIP — Manual Python Carving Required

> **Critical gotcha:** binwalk's built-in extraction fails because it requires the Java `jar` tool. Use Python to carve the ZIP manually. 7-Zip handles the non-standard Schneider ZIP format better than `unzip`.

```bash
python3 << 'EOF'
import subprocess, os

# ZIP start offset is constant (0xD00B); end offset varies per dump
dumps = [
  ('ExtRAM_20230629143509.bin', 0xD00B, 0xE8B2+22, 'prog1'),
  ('ExtRAM_20230629145014.bin', 0xD00B, 0xE8B2+22, 'prog2'),
  ('ExtRAM_20230629150519.bin', 0xD00B, 0xE8C5+22, 'prog3'),
  ('ExtRAM_20230629152024.bin', 0xD00B, 0xE8C5+22, 'prog4'),
  ('ExtRAM_20230629153528.bin', 0xD00B, 0xE8A0+22, 'prog5'),
  ('ExtRAM_20230629155033.bin', 0xD00B, 0xE8B8+22, 'prog6'),
  ('ExtRAM_20230629160538.bin', 0xD00B, 0xE8B8+22, 'prog7'),
]

for dump, start, end, name in dumps:
    with open(dump, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    with open(f'/tmp/{name}.zip', 'wb') as f:
        f.write(data)
    os.makedirs(f'/tmp/{name}', exist_ok=True)
    subprocess.run(['7z', 'e', f'/tmp/{name}.zip', f'-o/tmp/{name}/', '-y'],
                   capture_output=True)
    size = os.path.getsize(f'/tmp/{name}/entry')
    print(f'{name}: {size} bytes')
EOF
```

```
prog1: 49,417 bytes
prog2: 49,417 bytes   identical to prog1 — both legitimate baseline
prog3: 49,888 bytes   LARGER — first malicious modification
prog4: 49,888 bytes   identical to prog3
prog5: 49,144 bytes   SMALLER — rung deleted
prog6: 49,420 bytes   final state
prog7: 49,420 bytes   identical to prog6
```

The `entry` file is an **XML document** in EcoStruxure's `MetaDataEntity` format. It contains the complete I/O mapping, variable table, and ladder logic task structure.

### 5.5 Analyzing the Legitimate Program

```bash
strings /tmp/prog1/entry | head -80
```

The XML reveals:
- **Tasks:** What Floor (3 rungs), First Called (4), Second Called (5), Third Called (5), Floor Display (4), Elevator Door (11)
- **Variables:** LS1–LS3 (floor switches), LDR_CLOSE/LDR_OPEN (door sensors), ECB1–3 (call buttons), DOOR_OPEN/DOOR_CLOSE (motor outputs), SAME_CALL (Index 60 — call deduplication), DOOR_CNT (door counter), F1CALL–F4CALL (floor call flags)

### 5.6 Diffing Programs — The Four Changes

```bash
for p in prog2 prog3 prog4 prog5 prog6 prog7; do
  echo "=== prog1 vs $p ==="
  diff /tmp/prog1/entry /tmp/$p/entry | grep '^[<>]' | head -20
  echo ""
done
```

Programs 1 and 2 are identical (clean baseline). Programs 3–7 contain four specific changes:

---

#### Change 1 — SAME_CALL Variable Removed

```diff
< <MB>
<   <Index>60</Index>
<   <Symbol>SAME_CALL</Symbol>
<   <Comment>SameFloorCall</Comment>
< </MB>
```

The `SAME_CALL` memory bit (Index 60, comment "SameFloorCall") was deleted from the variable table. Based on its name and comment, this variable handled same-floor call deduplication. Its removal likely disrupted floor-call state transitions, consistent with the CCTV observation of the elevator stopping between floors.

> **Limitation:** To fully prove the physical effect, every rung in the baseline XML that used `SAME_CALL` as a contact or coil should be identified and traced. The `RungMetadata` XML elements do not expose this detail directly.

---

#### Change 2 — Door Timer Modified

```diff
< <Preset>10</Preset>
< <Base>OneSecond</Base>
---
> <Preset>5000</Preset>
> <Base>OneMilliSeconds</Base>
```

Timer duration change:

| | Preset | Base | Duration |
|---|---|---|---|
| Before | 10 | OneSecond | **10 seconds** |
| After | 5000 | OneMilliSeconds | **5000 ms = 5 seconds** |

The delay approximately halved. The base unit change from seconds to milliseconds also affects how the timer interacts with the PLC scan cycle. The CCTV shows abnormal door behavior consistent with altered timing.

> **Corrected claim:** The timer was changed to a millisecond-based preset of approximately 5 seconds. "Sub-second cycling" is not supported by this timer math alone — that conclusion requires additional evidence from CCTV frame timing, runtime timer values, or downstream rung analysis.

---

#### Change 3 — RungMetadata Removed from Elevator Door Subtask

```diff
< <RungMetadata>
<   <MainComment />
<   <Comments />
<   <Name />
<   <IsLadderSelected>false</IsLadderSelected>
< </RungMetadata>
```

One complete `RungMetadata` block was removed from the "Elevator Door" subtask. `RungMetadata` elements store rung-level metadata — they do not contain the actual ladder contacts, coils, or variable names. Therefore, the visible XML diff confirms a rung-list structural change, but the specific logic of the deleted rung cannot be determined from this diff alone.

| Evidence | What it supports |
|---|---|
| `RungMetadata` block removed | Confirms a structural change in the door-control rung list |
| Missing contact/coil body in diff | Prevents proving the exact safety logic from this XML diff alone |
| CCTV: doors open during movement | Consistent with a door-control interlock being affected, but not definitive proof of the deleted rung’s function |
| To prove definitively | Recover deleted rung's contacts/coils — requires EcoStruxure import or engineering backup |

---

#### Change 4 — Attacker Signature

```diff
< <Name>New Project</Name>
---
> <Name>SAFE Lab Mafia</Name>
```

The project was renamed "SAFE Lab Mafia" — a deliberate reference to the VCU SAFE Lab challenge creators. The comment "attaxk" (misspelling of "attack") was also embedded in programs 3 and 4.

---

### 5.7 The Final 4-Byte Change

```bash
python3 << 'EOF'
with open('ExtRAM_20230629155033.bin', 'rb') as f: d1 = f.read()
with open('ExtRAM_20230629160538.bin', 'rb') as f: d2 = f.read()

diffs = [(i, d1[i], d2[i]) for i in range(len(d1)) if d1[i] != d2[i]]
for offset, b1, b2 in diffs:
    print(f"0x{offset:04X}: 0x{b1:02X} ({b1:08b}) -> 0x{b2:02X} ({b2:08b})")
EOF
```

```
0x5D419: 0x8B (10001011) -> 0x88 (10001000)  bits 0 and 1 cleared
0x5D43F: 0x0D -> 0x0E                         DOOR_CNT: 13 -> 14
0x5D440: 0x00 -> 0x01                         lock flag: OFF -> ON
0x5D442: 0x08 -> 0x0F                         timer value updated
```

**Mapping chain for offset 0x5D419 → %Q0.0/%Q0.1:**

1. The project XML maps symbolic outputs: `DOOR_OPEN = %Q0.0`, `DOOR_CLOSE = %Q0.1`
2. Byte at 0x5D419 changed from `0x8B = 10001011` to `0x88 = 10001000`
3. Bits 0 and 1 cleared: `1 → 0` for both
4. Per M221 Programming Guide, the output image table stores `%Q0.x` states at bits 0–7 of the first output byte. Bits 0 and 1 correspond to `%Q0.0` and `%Q0.1`

```bash
# Verify symbolic-to-physical mapping from the project XML
grep -nE "DOOR_OPEN|DOOR_CLOSE|%Q0\.0|%Q0\.1" /tmp/prog1/entry /tmp/prog6/entry
```

> **Precise conclusion:** Both door motor outputs (%Q0.0 and %Q0.1) were de-energized in the final program state, alongside a door lock flag transitioning to 0x01. The PLC was no longer commanding either door motor. The doors remaining closed is consistent with mechanical state, the lock flag, or elevator brake behavior — the combination of de-energized outputs and lock flag change supports the sealed-door CCTV observation. A definitive proof that doors were "actively held shut" requires linking the lock flag to a specific output or mechanical actuator in the elevator hardware documentation.

### 5.8 OnChipRAM Correlation

```bash
files=(OnChipRAM_20230629143506.bin OnChipRAM_20230629145007.bin
       OnChipRAM_20230629150509.bin OnChipRAM_20230629152010.bin
       OnChipRAM_20230629153511.bin OnChipRAM_20230629155012.bin
       OnChipRAM_20230629160514.bin)

for i in 0 1 2 3 4 5; do
  count=$(cmp -l ${files[$i]} ${files[$((i+1))]} | wc -l)
  echo "window $i -> $((i+1)): $count bytes changed"
done
```

```
14:35 → 14:50:  7,654 bytes
14:50 → 15:05:  8,149 bytes   peak — most active execution
15:05 → 15:20:  6,647 bytes   lowest — elevator idle
15:20 → 15:35:  8,034 bytes   Kristi enters, attack active
15:35 → 15:50:  7,953 bytes
15:50 → 16:05:  7,493 bytes
```

OnChipRAM changes continuously because it stores live execution state — timers, counters, I/O image, PLC cycle counter. The peak at 14:50→15:05 reflects the malicious program executing most actively.

Hardware identity from strings:

```bash
strings OnChipRAM_20230629143506.bin | grep -iE "M221|firmware|1\.6"
```

**Result:** Model: M221CE16R | Firmware: 1.6.0.1 | MAC: 08:0F:44:C3:ED:D | Extension: TM3DM24R

---

## 6. Desktop Memory Forensics

### 6.1 Scope Limitation

> The memory dump was acquired on **June 22, 2023 — one week before the attack** on June 29. All findings describe the machine's state on June 22. This image cannot prove the machine was clean on the day of the attack.

### 6.2 System Identification

```bash
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \
  windows.envars --pid 3440 2>/dev/null \
  | grep -iE "username|computername"

vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \
  windows.netscan 2>/dev/null | grep -v "0.0.0.0\|::"
```

- Machine: DESKTOP-JKS05LO | User: **krist** (Kristi Wayne) | OS: Windows 10 Build 19041
- IP: 192.168.133.137 — corporate network, **different subnet** from OT (192.168.10.x)
- All connections to Microsoft/OneDrive/Edge services only. Zero connections to 192.168.10.45 (PLC)

The machine is on a physically separate subnet from the OT network. It cannot reach the PLC.

### 6.3 No Attack Tools — No Code Injection

- `windows.cmdline`: No EcoStruxure, no Schneider software, no ICS tools
- `windows.malfind`: No output — no injected shellcode, no hollowed processes at dump time
- `windows.netscan`: No connections to the OT network during the captured session

DumpIt was run twice: 14:26:13 and 14:32:55. Both output files appear in the Downloads folder confirming forensic acquisition by investigators.

### 6.4 Browser Activity — Researching ICS Security

```bash
python3 << 'EOF'
import re
with open('Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw', 'rb') as f:
    data = f.read()

targets = [b'safe.lab.vcu.edu', b'se.com', b'schneider',
           b'ecostruxure', b'bing.com/search']
seen = set()
for t in targets:
    idx = 0
    while True:
        idx = data.find(t, idx)
        if idx == -1: break
        chunk = data[max(0,idx-100):idx+200]
        urls = re.findall(
            b'https?://[a-zA-Z0-9][a-zA-Z0-9\\-\\./_?=&+#@:]{5,150}', chunk)
        for url in urls:
            decoded = url.decode('ascii','replace')
            if decoded not in seen:
                seen.add(decoded)
                print(decoded)
        idx += 1
EOF
```

Confirmed browser activity on June 22:
- Searched Bing: "vcu safe lab"
- Visited **https://safe.lab.vcu.edu** — the VCU SAFE Lab ICS security research group (challenge creators)
- Visited **https://se.com** — Schneider Electric
- EcoStruxure Machine Expert documentation loaded in Edge browser memory
- Normal activity: Gmail, YouTube ("To The Rescue! ⛑", PBS Firing Line), Google Calendar

Kristi was researching ICS security and Schneider Electric one week before the attack — she may have already been concerned about the system.

### 6.5 Suspicious USB Artifact — Relevance Unconfirmed

```bash
# AppCompatFlags records programs run from removable media
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \
  windows.registry.printkey \
  --offset 0x890e2424d000 \
  --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" \
  2>/dev/null

strings 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \
  | grep -iE "SIGN.MEDIA|setup64|19F1470"
```

`setup64.exe` was executed from D:\ removable media (volume signature SIGN.MEDIA=19F1470) at an unknown prior date. The binary's internal path structure:

```
D:\setup\drivers\audio\installs_the_realtek_ac_97_audio_driver\wdm5630\
  documents\documents11\secret\basic\updated\dao chich\final 007 spy\
```

Findings:
- The path structure is strongly suggestive of a surveillance tool disguised as a Realtek AC97 audio driver installer
- SHA256: `4E91DC44EC0888CF93C1100A0412525EB0A4ED69A023CB4401F7DE4B7F` — no VirusTotal results
- `D:\attacksfull` directory also referenced in memory
- The binary was not recovered or behaviorally analyzed in this report
- Execution date unknown (prior session, not in current Amcache)

> **Assessment:** This is a suspicious artifact requiring further investigation. Its relevance to the elevator attack is **undetermined** — it may be a separate incident. Stating it is definitively a spy tool requires behavioral analysis of the binary that was not performed here.

### 6.6 Victim Confirmation

| Evidence | Finding |
|---|---|
| Username | krist — confirmed CEO |
| Network | 192.168.133.x — corporate, physically isolated from OT |
| No ICS tools | No EcoStruxure, no Schneider software |
| No PLC connections | Zero connections to 192.168.10.45 |
| No OT subnet | Cannot reach 192.168.10.x from 192.168.133.x |
| Attacker hostname absent | DESKTOP-RSRBUGJ not found in memory |

Kristi Wayne is confirmed as the victim. Her machine was not involved in the attack.

---

## 7. Key References and How We Used Them

### 7.1 Kaspersky ICS-CERT — The Secrets of Schneider Electric's UMAS Protocol

**PDF:** https://ics-cert.kaspersky.com/wp-content/uploads/2023/03/kaspersky-ics-cert-the-secrets-of-schneider-electrics-umas-protocol-en.pdf  
**Web:** https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/

This was the most critical reference for network analysis. Without it, the PCAP would have been uninterpretable hex.

| What the paper documents | How we used it |
|---|---|
| UMAS uses Modbus FC90 (0x5A) | Immediately identified all PLC traffic as EcoStruxure sessions, not generic Modbus |
| StartDownload/BeginFileTransfer/FileTransfer/EndDownload command sequence | Identified all four uploads precisely from EndDownload timestamps |
| CVE-2020-28212 — UMAS authentication weaknesses | Explained why Employee-01 could upload programs without an authentication challenge in this environment. Schneider has since introduced configurable Application Password protection |
| QueryGetComInfo (0x7201) — session initialization | Recognized 20 occurrences in 4 clusters as EcoStruxure's documented connection behavior, distinguishing local interactive use from automated malware |
| Port 27127 device discovery protocol | Identified Employee-01's broadcast as the "Discover Devices" UI action — a human-initiated step, not automated |

### 7.2 Modicon M221 Logic Controller Programming Guide

**PDF:** https://pneumatykanet.pl/pub/przekierowanie/Modicon-M221-Logic-Controller-Programming-Guide-EN.pdf

| What the guide documents | How we used it |
|---|---|
| ExtRAM stores project file; OnChipRAM stores execution state | Explained why ExtRAM only changes during uploads while OnChipRAM changes continuously |
| Timer Base parameter: OneSecond, OneMilliSeconds, OneTenthSecond | Enabled precise calculation of before/after timer durations (10s → 5s) and appropriate hedging of the "sub-second cycling" claim |
| %I/%Q/%M addressing scheme | Made the XML variable table immediately interpretable — %Q0.0 = DOOR_OPEN, %Q0.1 = DOOR_CLOSE |
| Output image table layout | Informed interpretation that offset 0x5D419 corresponds to %Q0.x output states |
| System variables (%SW, %S) | Decoded OnChipRAM strings to confirm model, firmware, and MAC address |

---

## 8. Alternative Hypotheses Considered

| Hypothesis | Evidence For | Evidence Against | Verdict |
|---|---|---|---|
| Random mechanical malfunction | Elevator behaved abnormally | Four confirmed uploads from unauthorized host; malicious XML changes | Rejected |
| HMI caused malfunction | HMI has legitimate PLC access; 67,681 packets | No upload bursts from HMI — all traffic is normal polling | Rejected |
| Engineering WS caused attack | High PLC packet count | Constant 2,782 pkts/min = logger; no 0x41/0x42 upload commands observed | Rejected |
| Employee-01 remotely controlled | Unauthorized uploads occurred | No inbound C2 traffic; no external connections in PCAP | Not supported by PCAP; cannot exclude without host evidence |
| Local operator at Employee-01 | Self-initiated discovery; human-paced monitoring; upload timing matched physical events | No host image of Employee-01 to confirm user session | Best-supported by available evidence |
| Kristi Wayne involved | Researched ICS/Schneider one week prior | Machine on separate subnet; no PLC connections; no ICS tools; confirmed victim | Rejected |

---

## 9. MITRE ATT&CK for ICS Mapping

> Technique IDs should be verified against the current matrix at https://attack.mitre.org/matrices/ics/ before use in formal reporting.

| Observed Behavior | ATT&CK for ICS Technique |
|---|---|
| Unauthorized EcoStruxure engineering connection to PLC | Exploitation of Remote Services / Valid Accounts |
| Four malicious program uploads via UMAS | Program Download (T0843) |
| Live monitoring of PLC I/O state between uploads | Collection — I/O image monitoring |
| SAME_CALL variable removal | Modify Controller Tasking (T0821) |
| Door timer alteration | Manipulation of Control (T0831) |
| Elevator door-control rung-list change | Impair Process Control / Manipulation of Control |
| Targeted CEO specifically via elevator | Impact — manipulation of physical environment |
| Flat OT network, no segmentation | Architecture weakness enabling access (defender gap, not attacker TTP) |

---

## 10. ICS Threat Response and Human Impact Q&A

### Question 1: How can organizations avoid ICS threats, and what should they do if one occurs?

Organizations reduce ICS threats by combining secure architecture, access control, monitoring, and incident response procedures. The core weakness in this case was that employee workstations could reach the PLC network directly.

**Prevention:**

| Control | Purpose |
|---|---|
| Network segmentation | Separate corporate IT from OT using VLANs, firewalls, and controlled routing |
| Engineering workstation control | Allow only approved hosts to communicate with PLCs via programming protocols |
| PLC access control | Enable authentication (e.g., Application Password on M221) where supported |
| Allowlisting | Permit only expected hosts and protocols to reach PLCs |
| Monitoring | Alert on PLC uploads, programming commands, unexpected UMAS sources, and non-maintenance-window engineering activity |
| Verified backups | Maintain known-good PLC program backups for comparison and recovery |
| Change management | Require approval, logging, and validation for any PLC program change |
| Incident response drills | Prepare IT, OT, safety, legal, and management teams before an emergency |

**If an incident is already occurring:** the first priority is human safety, not evidence collection. Stop unsafe physical operation if needed, isolate affected systems only when safe, preserve evidence, and involve ICS engineers, safety personnel, and incident responders. The goal is to restore safe operation while preserving enough evidence to understand what happened.

### Question 2: Upon discovering a potential cyberattack on an elevator PLC, what are the first steps?

Because a PLC controls physical movement, the investigator must coordinate with safety personnel and ICS engineers before taking any action. Changing PLC state could affect people in or near the elevator.

| Step | Action | Reason |
|---|---|---|
| 1 | Confirm human safety | Identify whether anyone is trapped, injured, or at risk |
| 2 | Notify the correct teams | ICS engineers, safety officers, elevator technicians, incident response, management |
| 3 | Stabilize the process | Stop unsafe movement or isolate control paths if engineers determine it is safe |
| 4 | Preserve volatile evidence | Capture network traffic, PLC state, active sessions, workstation memory |
| 5 | Preserve non-volatile evidence | PLC project files, memory dumps, CCTV, workstation disk images, logs |
| 6 | Identify involved devices | IP, MAC, hostname, user account, expected vs actual device role |
| 7 | Compare PLC logic | Diff current program against a known-good baseline |
| 8 | Maintain chain of custody | Document collector, time, method, and storage for every artifact |

Do not directly modify PLC logic unless required for safety and authorized by qualified engineers. Document every action with a timestamp and justification.

### Question 3: What are the key moments of the attack, and how should organizations support affected people?

**Key moments reconstructed across evidence sources:**

| Time | Source | Event |
|---|---|---|
| Jun 29, 14:27:36 | PCAP | Employee-01 broadcast EcoStruxure discovery traffic |
| Jun 29, 14:27:51–53 | PCAP | First malicious PLC program upload confirmed |
| Jun 29, 15:00:24–25 | PCAP | Second program upload confirmed |
| Jun 29, 15:25:05–06 | PCAP + CCTV | Third upload — correlated with Kristi entering elevator |
| Jun 29, 15:25+ | CCTV + PLC logic | Unsafe elevator behavior begins |
| Jun 29, 15:35 | ExtRAM snapshot | Large memory changes; floor call flags active |
| Jun 29, 15:46:48–50 | PCAP | Fourth/final program upload — 'SAFE Lab Mafia' |
| Jun 29, 15:47:05 | PCAP | Employee-01 disconnected |
| Jun 29, 16:05 | ExtRAM snapshot | Final 4-byte change — door outputs de-energized |

**Human impact:** People trapped by ICS incidents may experience fear, anxiety, panic, sleep disruption, or lasting stress. A complete organizational response should include clear communication to the victim, protection of their privacy, avoidance of blame, and connection to professional support such as counseling, employee assistance programs, or medical care. Technical recovery and human care are both necessary parts of incident response.

### Question 4: What should a digital investigator do to help others during an ICS threat?

| Phase | Investigator Actions |
|---|---|
| Safety | Coordinate with safety staff and ICS engineers; support shutdown or isolation decisions |
| Preservation | Collect PCAP, PLC dumps, project files, HMI logs, CCTV, workstation evidence |
| Analysis | Identify unauthorized hosts, programming commands, logic changes, and timeline evidence |
| Containment | Support isolation of the affected workstation, engineering path, or PLC network segment when safe |
| Recovery | Help engineers restore known-good logic and validate that unsafe commands are no longer active |
| Monitoring | Watch for repeat engineering traffic, new uploads, or unauthorized reconnection attempts |
| Reporting | Document findings, affected assets, root cause, evidence, impact, and recommendations |
| Human support | Recommend communication, victim assistance, and post-incident care for affected staff |

The investigator's role is not only to prove what happened — it is also to reduce harm, support safe recovery, and give decision-makers clear information they can act on.

---

## 11. Complete Attack Timeline

| Timestamp | Event | Source |
|---|---|---|
| Jun 22, 14:26:13 | Kristi runs DumpIt — first memory acquisition | Desktop memory |
| Jun 22, 14:32:55 | Kristi runs DumpIt — second acquisition (this artifact) | Desktop memory |
| Jun 22 (prior, date unknown) | setup64.exe run from USB D:\ — suspicious artifact | AppCompatFlags |
| Jun 29, 14:27:36 | Employee-01 broadcasts EcoStruxure discovery (UDP port 27127) | PCAP |
| Jun 29, 14:27:45 | Employee-01 connects to PLC — QueryGetComInfo | PCAP |
| Jun 29, 14:27:51 | Program Upload #1 begins (549 pkts, ZIP header detected) | PCAP |
| Jun 29, 14:27:53 | EndDownload — malicious program #1 installed | PCAP |
| Jun 29, 14:28–14:59 | Live monitoring at 2 reads/sec — floor call flags watched | PCAP |
| Jun 29, 14:34:59 | Engineering WS logger starts — sequential memory scan begins | PCAP |
| Jun 29, 14:35:00 | ExtRAM snapshot #1 — PLC all-zero responses (post-upload) | ExtRAM |
| Jun 29, 14:50:00 | ExtRAM snapshot #2 — 7,317 bytes changed; PLC fully active | ExtRAM |
| Jun 29, 15:00:24 | Program Upload #2 begins (265 pkts) | PCAP |
| Jun 29, 15:00:25 | EndDownload — program #2 installed | PCAP |
| Jun 29, 15:05:00 | ExtRAM snapshot #3 — 18 bytes (idle) | ExtRAM |
| Jun 29, 15:20:00 | ExtRAM snapshot #4 — 18 bytes (idle) | ExtRAM |
| Jun 29, 15:25:00 | Floor call flags read as 0x00 — no calls pending | PCAP |
| Jun 29, 15:25:05 | Program Upload #3 begins — Kristi enters elevator (~same time) | PCAP + CCTV |
| Jun 29, 15:25:06 | EndDownload — 'attaxk' comment active; 1.251 sec transfer | PCAP |
| Jun 29, 15:25+ | CCTV: Elevator stuck between floors 2–3 | CCTV |
| Jun 29, 15:35:00 | ExtRAM snapshot #5 — 7,287 bytes; floor call flags = 0x01 | ExtRAM + PCAP |
| Jun 29, 15:35+ | CCTV: Doors open during movement, abnormal cycling | CCTV |
| Jun 29, 15:46:41 | Employee-01 reconnects — final session | PCAP |
| Jun 29, 15:46:48 | Program Upload #4 begins (141 pkts) | PCAP |
| Jun 29, 15:46:50 | EndDownload — 'SAFE Lab Mafia' name set | PCAP |
| Jun 29, 15:47:05 | Employee-01 disconnects — last packet 15:47:05.538 | PCAP |
| Jun 29, 15:47+ | CCTV: Doors sealed, Kristi trapped, emergency services called | CCTV |
| Jun 29, 15:50:00 | ExtRAM snapshot #6 — 6,324 bytes changed | ExtRAM |
| Jun 29, 16:05:00 | ExtRAM snapshot #7 — 4 bytes: door outputs de-energized, lock flag set | ExtRAM |
| Jun 29, ~16:00+ | CCTV: Ms. Wayne rescued by emergency responders | CCTV |

**Total from first upload to attacker disconnect:** 79 minutes 20 seconds

---

## 12. Conclusions

### 12.1 Attribution

| | |
|---|---|
| **Attacker workstation** | DESKTOP-RSRBUGJ — IP: 192.168.10.164 — MAC: 00:0c:29:5a:da:a3 |
| **Victim** | Kristi Wayne (CEO) — DESKTOP-JKS05LO — IP: 192.168.133.137 |
| **What** | 4 malicious EcoStruxure programs uploaded to elevator PLC |
| **When** | 14:27:51 – 15:47:05, Friday June 29, 2023 |
| **How** | EcoStruxure Machine Expert → UMAS FC90 → M221 PLC (no authentication observed) |
| **Remote compromise?** | No PCAP evidence during the capture; local interactive use best-supported |
| **Person-level attribution** | Requires physical identification of who was at DESKTOP-RSRBUGJ between 14:27 and 15:47 |

### 12.2 The Four Code Changes

| # | Change | Physical Effect | Confidence |
|---|---|---|---|
| 1 | SAME_CALL variable removed | Floor call state disrupted; elevator stuck | Medium (rung references not fully traced) |
| 2 | Timer: 10s/OneSecond → 5000ms/OneMilliSeconds | Door timing altered; delay approximately halved | High (math confirmed; sub-second claim not supported alone) |
| 3 | `RungMetadata` block removed from Elevator Door subtask | Confirms a door-control rung-list structural change; CCTV behavior is consistent with an interlock impact, but exact function is not proven | Medium (contact/coil content not recovered) |
| 4 | Project renamed 'SAFE Lab Mafia' + 'attaxk' comment | Deliberate attacker signature | High (directly observed in XML) |

### 12.3 Security Failures

1. **Flat OT network** — no VLANs, no firewall; employee workstations could reach the PLC (Purdue Model violation)
2. **No observed PLC authentication** — UMAS accepted engineering commands without credential challenge; consistent with known weaknesses in the M221's default configuration
3. **EcoStruxure on non-engineering workstation** — Employee-01 had full PLC programming capability
4. **No IDS/IPS on OT network** — attack ran undetected for 79 minutes
5. **No program integrity checking** — malicious code ran freely after upload

### 12.4 What Would Strengthen This Investigation

- Memory dump or disk image of DESKTOP-RSRBUGJ — user session evidence, installed software, logon events, Prefetch, Amcache
- Full rung logic (contacts/coils) for the removed `RungMetadata`/door-control rung area and all rungs referencing SAME_CALL
- CCTV timecode verified against a reference clock
- M221 memory map confirming exact offset of output image table
- Behavioral analysis of setup64.exe to determine what it does and whether it is connected to the elevator incident