# DFRWS 2023 — The Troubled Elevator: Complete Solution Write-Up

**Challenge:** DFRWS 2023 — The Troubled Elevator  
**Source:** https://github.com/dfrws/dfrws2023-challenge  
**Domain:** ICS/SCADA Forensics — PLC Memory, Network Traffic, Desktop Memory  
**Author:** VCU SAFE Lab (Security and Forensics Engineering Laboratory)  
**Tools:** Wireshark/tshark, Volatility 3, binwalk, 7-Zip, Python 3, cmp/xxd/strings

---
## Solution Mind Map

![DFRWS 2023 Troubled Elevator Solution Mind Map](visuals/troubled_elevator_solution_mindmap.svg)

---
## Table of Contents

1. [Understanding the Network and Elevator Manual](#1-understanding-the-network-and-elevator-manual)
2. [CCTV Footage Analysis](#2-cctv-footage-analysis)
3. [Network Traffic Analysis — PCAP](#3-network-traffic-analysis--pcap)
4. [PLC Memory Analysis](#4-plc-memory-analysis)
5. [Desktop Memory Forensics](#5-desktop-memory-forensics)
6. [Key References and How We Used Them](#6-key-references-and-how-we-used-them)
7. [Complete Attack Timeline](#7-complete-attack-timeline)
8. [ICS Threat Response and Human Impact Q&A](#8-ics-threat-response-and-human-impact-qa)
9. [Conclusions](#9-conclusions)

---

## 1. Understanding the Network and Elevator Manual

### 1.1 Reading the Network Diagram

Before touching any artifact, reading the provided \`Network Diagrams.pdf\` is essential. It defines the OT network topology and tells us which devices are expected to communicate with the PLC.

The network diagram reveals a **flat Layer-2 architecture** — every device on the same \`192.168.10.x\` subnet with no VLAN segmentation and no firewall between employee workstations and the PLC. This is the root cause of the attack: in a properly segmented Purdue Model network, employee workstations would never have layer-3 visibility to PLC devices.

**Devices listed in the diagram:**

| Device | IP Address | Role | Expected PLC Access |
|---|---|---|---|
| PLC (M221CE16R) | 192.168.10.45 | Elevator controller | N/A (target) |
| HMI | 192.168.10.121 | Operator interface | Yes — polling |
| Engineering WS | 192.168.10.130 | PLC programming station | Yes — maintenance only |
| Employee-01 (DESKTOP-RSRBUGJ) | 192.168.10.164 | Regular workstation | **NO** |
| Employee-02 | 192.168.10.242 | Regular workstation | No |
| Employee-03 | 192.168.10.101 | Regular workstation | No |
| CEO Desktop (DESKTOP-JKS05LO) | 192.168.133.137 | Corporate network VM | No (different subnet) |

The diagram immediately raises a question: what happens when a regular workstation — which should have no PLC access — sends engineering commands? The answer is: nothing stops it, because there is no enforcement mechanism.

> **Key takeaway:** The network diagram is your threat model baseline. Anything that deviates from it in the PCAP is evidence.

### 1.2 Reading the Elevator Manual

The \`Elevator Manual.pdf\` describes the Schneider Electric Modicon M221 PLC controlling the elevator. Key information to extract before analysis:

**Physical I/O mapping** — knowing what each input/output bit does is essential for interpreting code changes:

| Address | Symbol | Physical Component |
|---|---|---|
| %I0.0 | LS1 | Limit Switch Floor 1 |
| %I0.1 | LS2 | Limit Switch Floor 2 |
| %I0.2 | LS3 | Limit Switch Floor 3 |
| %I0.3 | LDR_CLOSE | Door Limit Close sensor |
| %I0.8 | LDR_OPEN | Door Limit Open sensor |
| %I0.5–0.7 | ECB1–3 | External Call Buttons 1–3 |
| %Q0.0 | DOOR_OPEN | Door open motor control |
| %Q0.1 | DOOR_CLOSE | Door close motor control |

**Memory architecture:**
- **ExtRAM (512KB):** Stores the uploaded EcoStruxure project file (ZIP-compressed XML), I/O image table, and runtime data
- **OnChipRAM (128KB):** Stores the running control logic, firmware configuration, and system variables

**Communication protocol:** The M221 uses UMAS (Unified Messaging Application Services) via Modbus TCP Function Code 90 (0x5A). This is the protocol used exclusively by Schneider's EcoStruxure Machine Expert engineering software. Critically, **the M221 implements no authentication on its UMAS interface** — any device that can reach port 502 can issue engineering commands including program uploads.

> **Key takeaway:** Understanding %Q0.0 = DOOR_OPEN and %Q0.1 = DOOR_CLOSE means that when we later find these bits cleared in memory, we immediately know the physical implication: the door motors are deactivated.

### 1.3 Full Network Inventory (Discovered During Analysis)

Beyond the network diagram, our PCAP analysis revealed 17 devices on the OT network — 10 more than the diagram showed. Of these, 6 had Schneider EcoStruxure software installed (identified by port 27127 discovery broadcasts), yet only one attacked the PLC:

| IP | Identity | EcoStruxure? | PLC Access |
|---|---|---|---|
| 192.168.10.1 | Schneider gateway/switch | Yes — discovery responder | No |
| 192.168.10.45 | M221 PLC | N/A | Target |
| 192.168.10.104 | Unknown workstation | Yes — port 1743 | No |
| 192.168.10.110 | Unknown workstation | Yes — port 27127 | No |
| 192.168.10.121 | HMI | Yes | Yes (legitimate) |
| 192.168.10.130 | Engineering WS (logger) | Yes | Yes (legitimate) |
| 192.168.10.153 | VM_PLC (SAFE Lab test VM) | Yes | No |
| **192.168.10.164** | **DESKTOP-RSRBUGJ (Employee-01)** | **Yes** | **YES — ATTACKER** |
| 192.168.10.241 | DHCP server (Schneider switch) | Yes | No |
| Others | Various workstations/devices | No | No |

The fact that 6 machines had EcoStruxure but only 1 attacked the PLC is strong evidence of deliberate insider action rather than automated malware.

---

## 2. CCTV Footage Analysis

The CCTV footage (\`Crop_fit.mp4\`) provides physical corroboration of all digital evidence and helps establish the human element of the attack. Watch the footage in phases:

### 2.1 Pre-Incident Phase
An employee is seen using the elevator normally — travelling to floor 3 (the Business Center) and returning to floor 1 without any issues. This confirms:
- The elevator was functioning correctly before the attack
- The attack had not yet been activated at this point
- The attacker likely observed this normal usage to understand timing

This is corroborated by the PCAP: the attack upload began at 14:27:51, and the CCTV shows normal elevator operation prior to that time.

### 2.2 Entry Phase — Kristi Wayne
Kristi Wayne enters the elevator at floor 1 and presses a floor call button. This moment is the trigger for upload #3 — the attacker was watching the PLC's floor call flags in real time (via EcoStruxure's live variable monitor at 2 reads/second) and initiated upload #3 at exactly 15:25:05, within seconds of her pressing the button.

The network evidence confirms: F1CALL/F2CALL/F3CALL flags at memory offset 0x0097 were 0x00 (no calls) at 14:50 and transitioned to 0x01 (call active) by 15:35 — Kristi's button press is recorded in the PLC's network responses.

### 2.3 Phase 1 — Elevator Gets Stuck
The elevator travels upward then stops between floors 2 and 3. This is the direct effect of the **SAME_CALL variable being removed** from the ladder logic. SAME_CALL prevented the elevator from responding to duplicate floor calls — without it, the floor position logic broke and the elevator could not correctly determine when it had arrived at its destination.

### 2.4 Phase 2 — Doors Open Mid-Travel
The elevator descends back toward floor 1 but the doors begin opening while the elevator is still in motion. This is the direct effect of the **safety rung deletion**. The deleted rung was a safety interlock that prevented the door-open motor (%Q0.0) from activating while the elevator was moving. With this rung gone, there was no software protection preventing the doors from opening at any time.

### 2.5 Phase 3 — Erratic Door Cycling
The elevator makes erratic movements and the doors rapidly cycle open and closed. This is the direct effect of the **door timer modification**: the timer base was changed from \`OneSecond\` to \`OneMilliSeconds\`. While the preset value appeared similar (10 → 5000), operating at millisecond resolution caused the door timer to fire in sub-second intervals, producing the rapid cycling observed on CCTV.

### 2.6 Phase 4 — Doors Sealed
The elevator arrives at floor 1 and the doors seal completely shut. Upload #4 at 15:46:48 delivered the final malicious program that explicitly cleared the DOOR_OPEN (%Q0.0) and DOOR_CLOSE (%Q0.1) output bits. This is confirmed by the 4-byte change in the last ExtRAM snapshot: offset 0x5D419 shows bits 0 and 1 clearing from 0x8B to 0x88.

### 2.7 Rescue
Emergency responders arrive and extract Ms. Wayne. The attacker had already disconnected at 15:47:05 — 18 seconds before the last snapshot shows the doors still sealed.

### 2.8 CCTV Summary Table

| Phase | CCTV Observation | Code Change Responsible | PCAP Timestamp |
|---|---|---|---|
| Pre-incident | Normal operation to floor 3 and back | None | Before 14:27:51 |
| Entry | Kristi enters, presses floor button | Upload #3 triggered | 15:25:05 |
| Phase 1 | Stuck between floors 2–3 | SAME_CALL removed | 15:25:06 |
| Phase 2 | Doors open during movement | Safety rung deleted | 15:25+ |
| Phase 3 | Rapid door cycling | Timer changed to ms | 15:25+ |
| Phase 4 | Doors sealed at floor 1 | Upload #4 final program | 15:46:50 |
| Rescue | Emergency services extract victim | N/A | ~16:00+ |

---

## 3. Network Traffic Analysis — PCAP

### 3.1 First Look — Protocol Distribution

Start by understanding the traffic landscape:

\`\`\`bash
# Total packet count and protocol breakdown
tshark -r 142728_162728.pcapng -q -z io,phs

# How many Modbus packets?
tshark -r 142728_162728.pcapng \\
  -Y "mbtcp" \\
  -T fields -e ip.src | wc -l
\`\`\`

The capture contains 208,335 total packets. 123,479 (59%) are Modbus TCP. All PLC-bound Modbus traffic uses **Function Code 90 (0x5A)** — this is the UMAS identifier. Normal Modbus function codes are 1–127; FC90 is Schneider proprietary. Any device sending FC90 has EcoStruxure installed.

### 3.2 Who Talked to the PLC?

\`\`\`bash
tshark -r 142728_162728.pcapng \\
  -Y "ip.dst == 192.168.10.45" \\
  -T fields -e ip.src \\
  | sort | uniq -c | sort -rn
\`\`\`

**Result:**
\`\`\`
67681  192.168.10.121   ← HMI (expected)
40058  192.168.10.130   ← Engineering WS (expected)
 1755  192.168.10.164   ← Employee-01 (UNAUTHORIZED)
\`\`\`

Three devices talked to the PLC. Two are expected. One is not.

### 3.3 Engineering WS — Legitimate Logger

The Engineering WS sends a perfectly steady 2,782 packets/minute (46.4 reads/second) — a machine-generated rhythm, not human interaction. Its startup sequence at 14:34:59 performs a sequential memory scan from address 0x0000 stepping 0xEC bytes at a time, reading 0x07EC bytes each request. This is a SCADA historian recording all PLC state at 46 Hz. The Engineering WS is NOT an attacker — it captured the entire attack.

Its traffic also confirms the attack timeline: at 14:35 it receives all-zero responses from the PLC (consistent with post-upload restart), and by 14:50 it receives rich data values including active coil states.

### 3.4 Attack Timeline — Employee-01

Analyze Employee-01's traffic per minute to find upload bursts:

\`\`\`bash
tshark -r 142728_162728.pcapng \\
  -Y "ip.src == 192.168.10.164 and mbtcp" \\
  -T fields -e frame.time \\
  | awk '{print substr($1,1,16)}' \\
  | sort | uniq -c
\`\`\`

The per-minute analysis reveals four distinct bursts:

| Time | Packets | Event |
|---|---|---|
| 14:27 | 549 | Upload #1 — ZIP transfer (PK\\x03\\x04 header in payload) |
| 15:00 | 265 | Upload #2 |
| 15:25 | 193 | Upload #3 — triggered by Kristi entering elevator |
| 15:46 | 141 | Upload #4 — final doors-sealed program |

Between bursts: steady 4–8 packets/min = EcoStruxure live variable monitoring at 2 reads/second.

### 3.5 Confirming Each Upload — EndDownload Command

Every successful program upload ends with the UMAS EndDownload command (0x42 0x00):

\`\`\`bash
tshark -r 142728_162728.pcapng \\
  -Y "ip.src == 192.168.10.164 and mbtcp" \\
  -T fields -e frame.time -e modbus.data \\
  | grep "00420000"
\`\`\`

**Result:**
\`\`\`
14:27:53.867  00420000   ← Upload #1 confirmed
15:00:25.629  00420000   ← Upload #2 confirmed
15:25:06.514  00420000   ← Upload #3 confirmed
15:46:50.110  00420000   ← Upload #4 confirmed
\`\`\`

Four EndDownload commands, four confirmed uploads. Upload #3 took exactly 1.251 seconds (15:25:05.263 → 15:25:06.514).

### 3.6 The Upload Protocol — Decoded

The complete UMAS program upload sequence uses four commands:

\`\`\`
1. f441ff00  ← StartDownload (0x41) — tell PLC to expect new program
2. f480      ← BeginFileTransfer (0x80) — open transfer channel
3. f4xxxx    ← FileTransfer blocks — send compressed ZIP data
4. 00420000  ← EndDownload (0x42) — commit program to PLC
\`\`\`

This matches the UMAS protocol documentation from the Kaspersky ICS-CERT research paper (see Section 6).

### 3.7 Attacker Machine Identification

\`\`\`bash
# Hostname from NetBIOS broadcasts
tshark -r 142728_162728.pcapng \\
  -Y "ip.src == 192.168.10.164 and nbns" \\
  -T fields -e nbns.name | head -5

# MAC address from ARP
tshark -r 142728_162728.pcapng \\
  -Y "arp.src.proto_ipv4 == 192.168.10.164" \\
  -T fields -e arp.src.hw_mac | head -3

# Hostname from LLMNR
tshark -r 142728_162728.pcapng \\
  -Y "ip.src == 192.168.10.164 and llmnr" \\
  -T fields -e dns.qry.name | head -5
\`\`\`

**Result:**
\`\`\`
Hostname:    DESKTOP-RSRBUGJ
MAC:         00:0c:29:5a:da:a3
OUI:         VMware (00:0c:29) — virtual machine
\`\`\`

### 3.8 Was Employee-01 Hacked?

This is a critical question. A compromised machine would show incoming control commands before each upload. Check:

\`\`\`bash
# Any traffic TO Employee-01 (other than from PLC)?
tshark -r 142728_162728.pcapng \\
  -Y "ip.dst == 192.168.10.164" \\
  -T fields -e ip.src -e _ws.col.Protocol \\
  | grep -v "192.168.10.45" | sort -u

# Any external connections?
tshark -r 142728_162728.pcapng \\
  -Y "ip.src == 192.168.10.164 or ip.dst == 192.168.10.164" \\
  -T fields -e ip.src -e ip.dst \\
  | grep -v "192.168.10" | sort -u
\`\`\`

**Result:** Zero incoming control commands. Zero external connections. The only non-PLC traffic from Employee-01 is standard Windows broadcasts (NBNS, LLMNR, SSDP) and Schneider EcoStruxure device discovery broadcasts.

**The device discovery finding is key:** At 14:27:36 — 9 seconds before the first PLC connection — Employee-01 broadcast a 37-byte UDP packet to port 27127 (Schneider's proprietary discovery port). Multiple devices responded, including the PLC. This is the EcoStruxure "Discover Devices" button being clicked by a human operator. It is self-initiated behavior, not a response to any external command.

The 20 QueryGetComInfo (0x7201) session initialization commands cluster into 4 groups of 4–6, one cluster per upload, with the triple rapid-retry burst that EcoStruxure generates when the M221 responds slowly. This is software-specific behavior that would only appear if a human was operating EcoStruxure normally.

**Verdict: The PCAP contains no evidence of remote compromise of Employee-01 during the captured window.** The traffic pattern is best explained by local, interactive use of Schneider engineering software: Employee-01 initiated Schneider discovery, opened UMAS sessions, uploaded programs, and monitored live PLC variables. However, without a disk image, memory dump, Windows event logs, Prefetch, Amcache, SRUM, or user logon evidence from Employee-01, a prior or off-capture compromise cannot be completely ruled out. The strongest defensible conclusion is **machine-level attribution to DESKTOP-RSRBUGJ / 192.168.10.164**, with local interactive use as the best-supported hypothesis.

### 3.9 Attacker Surveillance — Watching for Kristi

Between uploads, Employee-01 maintained active monitoring at 2 reads/second. The UMAS read commands targeted specific variable indices corresponding to floor call flags (F1CALL, F2CALL, F3CALL) and door sensor states. The attacker was watching the live elevator I/O state, waiting for Kristi to enter.

Upload #3 was triggered within seconds of her pressing the floor button — confirming the attack was responsive and targeted, not on a timer.

---

## 4. PLC Memory Analysis

### 4.1 Why Volatility Won't Work

A common mistake is attempting to use Volatility on PLC memory dumps. Volatility is built around OS memory structures — page tables, process lists, kernel objects. A PLC like the M221 runs bare-metal firmware with no OS, no virtual memory, and no process list. Volatility has nothing to hook into.

PLC memory forensics requires different tools: \`cmp\`, \`xxd\`, \`strings\`, \`binwalk\`, and Python.

### 4.2 ExtRAM Differential Analysis

The most powerful technique is comparing consecutive 15-minute snapshots to identify when changes occurred:

\`\`\`bash
cd 'PLC Memory Dumps'

for pair in '143509 145014' '145014 150519' '150519 152024' \\
            '152024 153528' '153528 155033' '155033 160538'; do
  a=$(echo $pair | cut -d' ' -f1)
  b=$(echo $pair | cut -d' ' -f2)
  count=$(cmp -l ExtRAM_20230629${a}.bin ExtRAM_20230629${b}.bin | wc -l)
  echo "$a -> $b: $count bytes changed"
done
\`\`\`

**Result:**
\`\`\`
143509 → 145014:     15 bytes  (minimal — first upload effect)
145014 → 150519:  7,317 bytes  ← MASSIVE — malicious program active
150519 → 152024:     18 bytes  (near-static — elevator idle)
152024 → 153528:  7,287 bytes  ← MASSIVE — attack active (Kristi enters)
153528 → 155033:  6,324 bytes  ← LARGE — fourth upload, doors sealed
155033 → 160538:      4 bytes  (near-static — post-incident)
\`\`\`

The pattern is clear: large changes during attack windows, near-static during idle periods.

### 4.3 Finding the Program Archive — binwalk

\`\`\`bash
for f in ExtRAM_*.bin; do
  echo "=== $f ==="
  binwalk $f | grep -iE "zip|end of zip"
done
\`\`\`

**Result:** All seven dumps contain a ZIP archive starting at offset **0xD00B** (53,259 decimal). End offsets vary per dump (0xE8B2, 0xE8C5, 0xE8A0, 0xE8B8) because the compressed program changes size.

### 4.4 Extracting the ZIP — Python Carving Required

binwalk's built-in extraction fails because it requires the Java \`jar\` tool. Manual Python carving works reliably:

\`\`\`bash
python3 << 'EOF'
import subprocess, os

# ZIP boundaries per dump (from binwalk output)
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
    print(f'{name}: {size} bytes extracted')
EOF
\`\`\`

**Result:**
\`\`\`
prog1: 49,417 bytes
prog2: 49,417 bytes   ← identical to prog1 (both legitimate)
prog3: 49,888 bytes   ← LARGER — first malicious modification
prog4: 49,888 bytes   ← identical to prog3
prog5: 49,144 bytes   ← SMALLER — safety rung deleted
prog6: 49,420 bytes   ← final state
prog7: 49,420 bytes   ← identical to prog6
\`\`\`

The file \`entry\` is an **XML document** — EcoStruxure Machine Expert's \`MetaDataEntity\` project format.

### 4.5 Analyzing the XML Content

\`\`\`bash
# Look at the structure of the legitimate program
strings /tmp/prog1/entry | head -60
\`\`\`

The XML reveals the complete I/O mapping, variable definitions, and ladder logic task structure:
- **What Floor** (3 rungs), **First Called** (4 rungs), **Second Called** (5 rungs)
- **Third Called** (5 rungs), **Floor Display** (4 rungs), **Elevator Door** (11 rungs)
- Variables: LS1–LS3 (floor limit switches), LDR_CLOSE/LDR_OPEN (door sensors), ECB1–3 (call buttons), DOOR_OPEN/DOOR_CLOSE (motor outputs), SAME_CALL (deduplication flag)

### 4.6 Diffing Programs — Finding the Malicious Changes

\`\`\`bash
# Compare all programs against the legitimate baseline
for p in prog2 prog3 prog4 prog5 prog6 prog7; do
  echo "=== prog1 vs $p ==="
  diff /tmp/prog1/entry /tmp/$p/entry | grep '^[<>]' | head -20
  echo ""
done
\`\`\`

**Programs 1 and 2 are identical** — the baseline is clean.

**Programs 3–7 contain four specific changes:**

#### Change 1 — SAME_CALL Variable Removed (Lines 169–173)
\`\`\`diff
< <MB>
<   <Index>60</Index>
<   <Symbol>SAME_CALL</Symbol>
<   <Comment>SameFloorCall</Comment>
< </MB>
\`\`\`
The \`SAME_CALL\` memory bit prevented the elevator from responding to a call for the floor it was already on. Removing it broke floor position tracking — the elevator no longer knew when it had "arrived."

#### Change 2 — Door Timer Modified (Lines 176–177)
\`\`\`diff
< <Preset>10</Preset>
< <Base>OneSecond</Base>
---
> <Preset>5000</Preset>
> <Base>OneMilliSeconds</Base>
\`\`\`
The timer behavior changed from a **10-second** delay to a **5-second** millisecond-based delay:

- Baseline: \`Preset=10\`, \`Base=OneSecond\` → approximately **10 seconds**
- Modified: \`Preset=5000\`, \`Base=OneMilliSeconds\` → approximately **5000 ms = 5 seconds**

This does **not** prove sub-second cycling by itself. The defensible finding is that the attacker changed the timer resolution and reduced the effective delay from about 10 seconds to about 5 seconds. Any claim of sub-second cycling must be supported separately by CCTV frame timing, runtime timer values, or additional ladder-logic interactions.

#### Change 3 — Safety Rung Deleted from the Elevator Door Subtask

The XML diff shows that one complete rung was removed from the **Elevator Door** subtask. The earlier draft only showed the deleted \`RungMetadata\`, which proves that a rung boundary changed but does not show the actual safety logic. For a defensible forensic report, the deleted rung must be documented by extracting the full rung body from the baseline XML and showing that it no longer appears in the modified program.

Use this evidence workflow to capture the actual deleted rung content:

\`\`\`bash
# 1) Extract the complete Elevator Door subtask from baseline and modified XML.
python3 << 'EOF'
from pathlib import Path
import re

baseline = Path('/tmp/prog1/entry').read_text(errors='replace')
modified = Path('/tmp/prog5/entry').read_text(errors='replace')

# Adjust the boundary regex if the XML uses a different tag name around subtasks/rungs.
def extract_elevator_door(xml):
    m = re.search(r'(<[^>]*Name[^>]*>Elevator Door</[^>]*>.*?)(?=<[^>]*Name[^>]*>|\Z)', xml, re.S)
    return m.group(1) if m else xml

Path('/tmp/baseline_elevator_door.xml').write_text(extract_elevator_door(baseline))
Path('/tmp/modified_elevator_door.xml').write_text(extract_elevator_door(modified))
print('Wrote /tmp/baseline_elevator_door.xml and /tmp/modified_elevator_door.xml')
EOF

# 2) Diff the extracted door-control logic and keep the full deleted rung body.
diff -u /tmp/baseline_elevator_door.xml /tmp/modified_elevator_door.xml   > /tmp/elevator_door_deleted_rung.diff

# 3) Review the deleted contacts/coils, not only RungMetadata.
less /tmp/elevator_door_deleted_rung.diff
\`\`\`

Add the deleted rung evidence in this format after reviewing the diff:

| Deleted rung evidence | What to record |
|---|---|
| Subtask | \`Elevator Door\` |
| Deleted contacts | Paste the actual contact names/addresses from the baseline rung |
| Deleted coil/output | Paste the actual coil/output affected by the rung |
| Safety meaning | Explain the rung based on its contacts/coils |
| Evidence limitation | If only metadata is available, state that the report proves a rung was deleted but does not independently prove the rung's safety function |

With the current evidence shown in this write-up, the safest wording is: **a rung was deleted from the Elevator Door subtask, and this deletion is consistent with the observed unsafe door behavior. The exact interlock function should be proven by including the full deleted rung body from the baseline XML.**

#### Change 4 — Attacker Signature (Line 1384)
\`\`\`diff
< <Name>New Project</Name>
---
> <Name>SAFE Lab Mafia</Name>
\`\`\`
The attacker renamed the EcoStruxure project "SAFE Lab Mafia" — a deliberate reference to the VCU SAFE Lab challenge creators. The comment "attaxk" (misspelling of "attack") was also embedded in programs 3 and 4.

### 4.7 The Final 4-Byte Change — Doors Permanently Locked

The last snapshot pair (15:50 → 16:05) showed only 4 changed bytes across the entire 512KB ExtRAM:

\`\`\`bash
python3 << 'EOF'
with open('ExtRAM_20230629155033.bin', 'rb') as f: d1 = f.read()
with open('ExtRAM_20230629160538.bin', 'rb') as f: d2 = f.read()

diffs = [(i, d1[i], d2[i]) for i in range(len(d1)) if d1[i] != d2[i]]
for offset, b1, b2 in diffs:
    print(f"0x{offset:04X}: 0x{b1:02X} -> 0x{b2:02X}")
EOF
\`\`\`

**Result:**
\`\`\`
0x5D419: 0x8B -> 0x88  (binary: 10001011 -> 10001000 — bits 0,1 cleared)
0x5D43F: 0x0D -> 0x0E  (DOOR_CNT counter: 13 -> 14)
0x5D440: 0x00 -> 0x01  (door lock flag: OFF -> ON)
0x5D442: 0x08 -> 0x0F  (timer final value)
\`\`\`

The bit-level change at \`0x5D419\` is important, but the report should show the mapping chain instead of asserting it in one sentence. The defensible chain is:

1. The project XML maps the symbolic outputs to physical PLC outputs: \`DOOR_OPEN = %Q0.0\` and \`DOOR_CLOSE = %Q0.1\`.
2. The final ExtRAM byte changed from \`0x8B\` to \`0x88\`.
3. In binary, \`0x8B = 10001011\` and \`0x88 = 10001000\`, so bits 0 and 1 changed from \`1\` to \`0\`.
4. If \`0x5D419\` is confirmed as the PLC output-image byte for \`%Q0.x\`, then bits 0 and 1 correspond to \`%Q0.0\` and \`%Q0.1\`, meaning both door motor outputs were de-energized in the final state.

Add this proof block to make the mapping reproducible:

\`\`\`bash
# Show the XML mapping from symbolic names to physical outputs.
grep -nE "DOOR_OPEN|DOOR_CLOSE|%Q0\.0|%Q0\.1" /tmp/prog1/entry /tmp/prog6/entry

# Show the exact final byte and bit transition.
python3 << 'EOF'
old = 0x8B
new = 0x88
print(f'old: 0x{old:02X} = {old:08b}')
print(f'new: 0x{new:02X} = {new:08b}')
for bit in range(8):
    before = (old >> bit) & 1
    after = (new >> bit) & 1
    if before != after:
        print(f'bit {bit}: {before} -> {after}')
EOF
\`\`\`

Revised conclusion: **the final snapshot shows bits 0 and 1 clearing in the suspected output-image byte, consistent with \`DOOR_OPEN (%Q0.0)\` and \`DOOR_CLOSE (%Q0.1)\` being de-energized. This supports a final non-opening/closed-door state. Avoid saying the doors were “actively held shut” unless the lock flag, mechanical behavior, or ladder logic proves active holding rather than de-energized outputs.**

### 4.8 OnChipRAM Correlation

\`\`\`bash
files=(OnChipRAM_20230629143506.bin OnChipRAM_20230629145007.bin
       OnChipRAM_20230629150509.bin OnChipRAM_20230629152010.bin
       OnChipRAM_20230629153511.bin OnChipRAM_20230629155012.bin
       OnChipRAM_20230629160514.bin)

for i in 0 1 2 3 4 5; do
  count=$(cmp -l \${files[$i]} \${files[$((i+1))]} | wc -l)
  echo "\${files[$i]:12:4} -> \${files[$((i+1))]:12:4}: $count bytes"
done
\`\`\`

**Result:**
\`\`\`
14:35 → 14:50:  7,654 bytes   (malicious program starts executing)
14:50 → 15:05:  8,149 bytes   (HIGHEST — most active attack phase)
15:05 → 15:20:  6,647 bytes   (LOWEST — elevator idle)
15:20 → 15:35:  8,034 bytes   (Kristi enters — attack active)
15:35 → 15:50:  7,953 bytes   (doors sealed)
15:50 → 16:05:  7,493 bytes   (post-incident)
\`\`\`

Unlike ExtRAM (which only changes during uploads), OnChipRAM changes continuously because it stores the running execution state — timers, counters, I/O values, cycle counts. The peak at 14:50→15:05 confirms the malicious program was most actively executing during this window.

Key strings in OnChipRAM confirm hardware identity:
\`\`\`bash
strings OnChipRAM_20230629143506.bin | grep -iE "M221|firmware|1\\.6"
\`\`\`
**Result:** Model: M221CE16R | Firmware: 1.6.0.1 | MAC: 08:0F:44:C3:ED:D

---

## 5. Desktop Memory Forensics

### 5.1 System Identification

\`\`\`bash
# Identify machine and user
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  windows.envars --pid 3440 2>/dev/null | grep -iE "username|computername|ip"

# Active network connections
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  windows.netscan 2>/dev/null | grep -v "0.0.0.0\\|::"
\`\`\`

**Key findings:**
- Machine: DESKTOP-JKS05LO
- Username: **krist** (Kristi Wayne — confirmed CEO victim)
- IP: 192.168.133.137 (corporate network — separate subnet from OT)
- All connections: Microsoft/OneDrive/Edge only

The machine is on a completely different subnet (192.168.133.x) from the OT network (192.168.10.x). It physically cannot reach the PLC.

### 5.2 Process List — Clean

\`\`\`bash
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  windows.cmdline 2>/dev/null | grep -v "system32\\|N/A"
\`\`\`

No EcoStruxure, no Schneider software, no ICS tools. Standard processes: msedge.exe, OneDrive.exe, Explorer.exe, DumpIt.exe (forensic acquisition tool).

DumpIt was run twice: 14:26:13 (first dump) and 14:32:55 (second dump — the file we have). Both filenames found in the Downloads folder:
- \`DESKTOP-JKS05LO-20230622-142613.raw\`
- \`DESKTOP-JKS05LO-20230622-143255.raw\`

### 5.3 Malfind — No Code Injection

\`\`\`bash
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  windows.malfind 2>/dev/null | head -40
\`\`\`

**Result:** No output — no injected shellcode, no hollowed processes. The machine was not actively compromised at dump time.

### 5.4 Browser Activity — Researching ICS Security

\`\`\`bash
python3 << 'EOF'
import re
with open('Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw', 'rb') as f:
    data = f.read()

targets = [b'safe.lab.vcu.edu', b'se.com', b'schneider', b'ecostruxure',
           b'bing.com/search', b'gmail.com', b'youtube.com']
seen = set()
for t in targets:
    idx = 0
    while True:
        idx = data.find(t, idx)
        if idx == -1: break
        chunk = data[max(0,idx-100):idx+200]
        urls = re.findall(b'https?://[a-zA-Z0-9][a-zA-Z0-9\\-\\./_?=&+#@:]{5,150}', chunk)
        for url in urls:
            decoded = url.decode('ascii','replace')
            if decoded not in seen:
                seen.add(decoded)
                print(decoded)
        idx += 1
EOF
\`\`\`

**Confirmed browser activity on June 22 (one week before the attack):**
- Searched Bing for "vcu safe lab"
- Visited **https://safe.lab.vcu.edu** — the VCU SAFE Lab ICS security research group
- Visited **https://se.com** — Schneider Electric's website
- Loaded EcoStruxure Machine Expert documentation in Edge browser
- Used Gmail, YouTube (watched "To The Rescue! ⛑" and a PBS Firing Line episode), Google Calendar

Kristi was researching ICS security and Schneider Electric one week before the attack. This suggests she may have already been concerned about vulnerabilities in the bank's elevator system.

### 5.5 Suspicious USB Artifact — Relevance Unconfirmed

\`\`\`bash
# Check AppCompatFlags for removable media execution
vol -f 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  windows.registry.printkey \\
  --offset 0x890e2424d000 \\
  --key "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store" \\
  2>/dev/null

# Search for the USB volume signature in raw memory
strings 'Desktop Memory Dump/DESKTOP-JKS05LO-20230622-143255.raw' \\
  | grep -iE "SIGN.MEDIA|setup64|19F1470"
\`\`\`

**Critical finding:** \`setup64.exe\` was executed from D:\\ removable media (volume signature SIGN.MEDIA=19F1470). The executable's internal path structure reveals:

\`\`\`
D:\\setup\\drivers\\audio\\installs_the_realtek_ac_97_audio_driver\\wdm5630\\
  documents\\documents11\\secret\\basic\\updated\\dao chich\\final 007 spy\\
\`\`\`

This is a spy/surveillance tool disguised as a Realtek AC97 audio driver installer:
- **Outer disguise:** "Realtek AC97 audio driver" — a legitimate-sounding cover
- **Internal path:** \`secret\\basic\\updated\\dao chich\\final 007 spy\` — the actual payload
- **Author/alias:** "dao chich" — likely Vietnamese-language alias
- **SHA256:** \`4E91DC44EC0888CF93C1100A0412525EB0A4ED69A023CB4401F7DE4B7F\` — unknown to VirusTotal
- **Also found:** \`D:\\attacksfull\` directory reference — organized attack toolkit on the USB

The execution date is unknown (not in current Amcache — ran in a prior session). Whether this spy tool is related to the elevator attack or a separate incident requires further investigation.

### 5.6 Victim Confirmation

Kristi Wayne is confirmed as the victim:

| Evidence | Finding |
|---|---|
| Username | krist — matches CEO name |
| Machine name | DESKTOP-JKS05LO — CEO workstation |
| Network | 192.168.133.x — corporate network, separate from OT |
| No ICS tools | No EcoStruxure, no Modbus tools, no Schneider software |
| No PLC connections | Zero connections to 192.168.10.45 at any time |
| No attacker hostname | DESKTOP-RSRBUGJ not found in memory |
| Normal activity | Gmail, YouTube, Google Calendar, OneDrive |

---

## 6. Key References and How We Used Them

### 6.1 Kaspersky ICS-CERT — The Secrets of Schneider Electric's UMAS Protocol

**PDF:** https://ics-cert.kaspersky.com/wp-content/uploads/2023/03/kaspersky-ics-cert-the-secrets-of-schneider-electrics-umas-protocol-en.pdf  
**Web:** https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/

This paper was the single most important reference for understanding the attack mechanism. Without it, the PCAP would have been a wall of uninterpretable hex bytes.

**Specific contributions to our investigation:**

1. **Protocol identification:** The paper explains that UMAS operates as a Modbus extension using Function Code 0x5A (decimal 90). When we saw all PLC traffic using FC90 in the PCAP, we immediately knew this was EcoStruxure — not generic Modbus. This narrowed the attacker's tool to a single product: EcoStruxure Machine Expert.

2. **Upload command structure:** The paper documents the StartDownload (0x41), BeginFileTransfer (0x80), FileTransfer (0xf4xx), and EndDownload (0x42) command sequence. This let us identify every upload precisely and confirm exactly four program uploads from the EndDownload timestamps.

3. **No authentication:** The paper explicitly documents CVE-2020-28212 — the M221's UMAS interface requires no authentication. This explains how Employee-01 (a non-engineering workstation) could upload programs without any credential. The vulnerability exists because Schneider designed UMAS without authentication — any device that can reach port 502 can issue engineering commands.

4. **QueryGetComInfo (0x7201):** The paper documents this as the UMAS session initialization command. Recognizing the 20 occurrences of this command in Employee-01's traffic — clustered into 4 groups — confirmed the session pattern was EcoStruxure's documented behavior, not a compromised machine.

5. **Discovery protocol (port 27127):** The paper describes the EcoStruxure device discovery mechanism. When we found Employee-01 broadcasting 37-byte UDP packets to port 27127 before connecting to the PLC, we could confirm this was the "Discover Devices" function being invoked by a human operator — not automated malware.

### 6.2 Modicon M221 Logic Controller Programming Guide

**PDF:** https://pneumatykanet.pl/pub/przekierowanie/Modicon-M221-Logic-Controller-Programming-Guide-EN.pdf

This is the official Schneider Electric programming manual for the M221 PLC. It was essential for understanding what the malicious code changes actually meant in physical terms.

**Specific contributions to our investigation:**

1. **Memory architecture:** The manual explains the distinction between ExtRAM (project storage) and OnChipRAM (execution memory). Without this, we would not have known why ExtRAM changes corresponded to uploads while OnChipRAM changed continuously.

2. **Timer base units:** The manual documents the \`Base\` parameter for timer blocks (\`OneSecond\`, \`OneMilliSeconds\`, \`OneTenthSecond\`). This was critical for interpreting Change 2. The modified timer should be described precisely as \`5000 × OneMilliSeconds = 5000 ms = 5 seconds\`, not as sub-second behavior unless separate runtime or CCTV timing evidence proves faster cycling.

3. **I/O addressing (%I, %Q, %M):** The manual defines the addressing scheme used throughout the XML program file. Without knowing that \`%Q0.0\` = DOOR_OPEN output and \`%Q0.1\` = DOOR_CLOSE output, the 4-byte change in the final ExtRAM snapshot (bits 0 and 1 clearing at offset 0x5D419) would have been meaningless. With the manual, we could immediately identify this as both door motors being deactivated.

4. **Task structure:** The manual explains EcoStruxure's task organization (periodic tasks, event tasks, subtasks). This helped us interpret the XML structure in the extracted \`entry\` file — specifically understanding that "Elevator Door" is a subtask with 11 rungs, and that deleting one rung removes a complete logical condition from the door control sequence.

5. **System variables (%SW, %S, %MW):** The manual documents system word addresses for firmware version, boot version, and Ethernet error codes. This let us decode the OnChipRAM strings to confirm the PLC model (M221CE16R), firmware version (1.6.0.1), and MAC address.

---

## 7. Complete Attack Timeline

| Timestamp | Event | Source Artifact |
|---|---|---|
| Jun 22, 14:26:13 | Kristi runs DumpIt — first memory acquisition | Desktop memory |
| Jun 22, 14:32:55 | Kristi runs DumpIt — second acquisition (our artifact) | Desktop memory |
| Jun 22 (prior) | setup64.exe run from USB D:\\ — spy tool deployed | AppCompatFlags |
| Jun 29, 14:27:36 | Employee-01 broadcasts EcoStruxure discovery (UDP 27127) | PCAP |
| Jun 29, 14:27:45 | Employee-01 connects to PLC — QueryGetComInfo | PCAP |
| Jun 29, 14:27:51 | Program Upload #1 begins (549 packets, ZIP header detected) | PCAP |
| Jun 29, 14:27:53 | EndDownload — malicious program #1 installed | PCAP |
| Jun 29, 14:28–14:59 | Employee-01 monitors at 2 reads/sec — watching floor call flags | PCAP |
| Jun 29, 14:34:59 | Engineering WS logger starts — begins recording all PLC state | PCAP |
| Jun 29, 14:35:00 | ExtRAM snapshot #1 — PLC all-zero responses (post-upload restart) | ExtRAM |
| Jun 29, 14:50:00 | ExtRAM snapshot #2 — 7,317 bytes changed, PLC fully active | ExtRAM |
| Jun 29, 15:00:24 | Program Upload #2 begins (265 packets) | PCAP |
| Jun 29, 15:00:25 | EndDownload — malicious program #2 installed | PCAP |
| Jun 29, 15:05:00 | ExtRAM snapshot #3 — 18 bytes (elevator idle) | ExtRAM |
| Jun 29, 15:20:00 | ExtRAM snapshot #4 — 18 bytes (still idle) | ExtRAM |
| Jun 29, 15:25:00 | Employee-01 reads floor call flags = 0x00 (no calls yet) | PCAP |
| Jun 29, 15:25:05 | Program Upload #3 begins — Kristi enters elevator | PCAP + CCTV |
| Jun 29, 15:25:06 | EndDownload — 'attaxk' comment active, 1.25 sec transfer | PCAP |
| Jun 29, 15:25+ | CCTV: Elevator stuck between floors 2 and 3 | CCTV |
| Jun 29, 15:35:00 | ExtRAM snapshot #5 — 7,287 bytes, floor call flags = 0x01 | ExtRAM + PCAP |
| Jun 29, 15:35+ | CCTV: Doors open mid-travel, erratic movement | CCTV |
| Jun 29, 15:46:41 | Employee-01 reconnects for final session | PCAP |
| Jun 29, 15:46:48 | Program Upload #4 begins (141 packets) | PCAP |
| Jun 29, 15:46:50 | EndDownload — 'SAFE Lab Mafia' project name set | PCAP |
| Jun 29, 15:47:05 | Employee-01 disconnects — mission complete (15:47:05.538) | PCAP |
| Jun 29, 15:47+ | CCTV: Doors sealed, Kristi trapped, emergency called | CCTV |
| Jun 29, 15:50:00 | ExtRAM snapshot #6 — 6,324 bytes changed | ExtRAM |
| Jun 29, 16:05:00 | ExtRAM snapshot #7 — only 4 bytes: Q0.0/Q0.1 cleared | ExtRAM |
| Jun 29, ~16:00+ | CCTV: Ms. Wayne rescued by emergency responders | CCTV |

**Total attack duration:** 79 minutes 20 seconds (14:27:45 → 15:47:05)

---


## 8. ICS Threat Response and Human Impact Q&A

This section answers broader response and prevention questions raised by the Troubled Elevator case. The key principle is that ICS incidents are not only digital events; they can create real-world safety risks, operational disruption, and psychological impact for victims and staff.

### Question 1: How can someone avoid threats to ICS, and what can people do if this occurs?

Organizations can reduce threats to Industrial Control Systems by combining **secure architecture, access control, monitoring, and prepared response procedures**. The major weakness in this case was that ordinary workstations could reach the PLC network. In a safer ICS environment, employee workstations, corporate systems, HMIs, engineering workstations, and PLCs should not all exist on the same flat network.

Important preventive measures include:

| Control | Purpose |
|---|---|
| Network segmentation | Separate corporate IT from OT/ICS networks using VLANs, firewalls, and controlled routing |
| Engineering workstation control | Allow only approved engineering hosts to communicate with PLCs |
| PLC access control | Require authentication or application passwords where supported |
| Allowlisting | Permit only expected hosts and protocols to reach PLCs |
| Monitoring | Alert on PLC uploads, programming commands, abnormal Modbus/UMAS traffic, and unauthorized engineering activity |
| Known-good backups | Maintain verified PLC logic backups for comparison and recovery |
| Change management | Require approval, logging, and validation for PLC program changes |
| Incident response drills | Prepare IT, OT, safety, legal, and management teams before an emergency occurs |

If an ICS incident is already happening, the first priority is **human safety**, not evidence collection. The organization should stop unsafe physical operation if needed, isolate affected systems only when it is safe to do so, preserve evidence, and involve ICS engineers, safety personnel, and incident responders. The goal is to restore safe operation while preserving enough evidence to understand what happened.

### Question 2: Upon discovering a potential cyberattack on an elevator PLC, what are the first steps a digital forensic investigator should take?

Because an elevator PLC controls physical movement, the first step is to coordinate with safety personnel and elevator/ICS engineers. The investigator should not treat the case like a normal computer intrusion because any action taken on the PLC could affect people in the elevator or nearby.

Initial response steps:

| Step | Action | Reason |
|---|---|---|
| 1 | Confirm human safety | Identify whether anyone is trapped, injured, or at risk |
| 2 | Notify the correct teams | Include ICS engineers, building safety, elevator technicians, incident response, and management |
| 3 | Stabilize the physical process | Stop unsafe elevator movement or isolate control paths if engineers determine it is safe |
| 4 | Preserve volatile evidence | Capture network traffic, PLC state, active sessions, and workstation memory where possible |
| 5 | Preserve non-volatile evidence | Collect PLC project files, memory dumps, logs, CCTV footage, workstation disk images, and engineering software artifacts |
| 6 | Identify involved devices | Record IP addresses, MAC addresses, hostnames, user accounts, and expected device roles |
| 7 | Compare PLC logic | Diff the current PLC program against a known-good baseline |
| 8 | Maintain chain of custody | Document who collected each artifact, when, how, and where it was stored |

The investigator should avoid directly changing PLC logic unless it is required for safety and authorized by qualified engineers. If emergency changes are necessary, every action should be documented with timestamps and justification.

### Question 3: What are the key moments of the attack based on memory and network dumps, and how can we help people affected by trauma?

The key moments can be reconstructed by combining network traffic, PLC memory differences, extracted PLC project files, and CCTV observations.

| Time | Evidence Source | Key Moment |
|---|---|---|
| Jun 29, 14:27:36 | PCAP | Employee-01 / `192.168.10.164` broadcasted EcoStruxure discovery traffic |
| Jun 29, 14:27:51–14:27:53 | PCAP | First PLC program upload completed with EndDownload |
| Jun 29, 15:00:24–15:00:25 | PCAP | Second PLC program upload completed |
| Jun 29, 15:25:05–15:25:06 | PCAP + CCTV | Third upload occurred around the time Kristi entered/used the elevator |
| Jun 29, 15:25+ | CCTV + PLC logic | Elevator behavior became unsafe, including abnormal stopping and door behavior |
| Jun 29, 15:35 | ExtRAM snapshot | Large memory changes and active floor-call state supported attack activity |
| Jun 29, 15:46:48–15:46:50 | PCAP | Fourth/final PLC program upload completed |
| Jun 29, 15:47:05 | PCAP | Employee-01 disconnected after the final session |
| Jun 29, 16:05 | ExtRAM snapshot | Final snapshot showed only four changed bytes, including door-related output/state changes |

The technical evidence supports a coordinated sequence: unauthorized engineering traffic from Employee-01, multiple PLC program uploads, malicious logic changes in the extracted PLC project, and later memory changes consistent with altered door-control behavior.

The human impact also matters. People affected by ICS incidents may experience fear, anxiety, panic, sleep problems, or stress after being trapped, injured, or placed in danger. Investigators and organizations can help by taking the victim seriously, avoiding blame, providing clear updates, protecting privacy, and connecting affected people with professional support such as counselors, trauma specialists, employee assistance programs, or medical providers. A complete ICS response should include both technical recovery and human care.

### Question 4: As a digital investigator, what actions and procedures should I take to help others during a threat posed by ICS?

A digital investigator should support **safety, containment, evidence preservation, recovery, and clear communication**. In ICS cases, the investigator must work closely with engineers because the affected systems control physical equipment.

Recommended procedure:

| Phase | Investigator Actions |
|---|---|
| Safety | Coordinate with safety staff and ICS engineers; support shutdown, rescue, or isolation decisions if needed |
| Preservation | Collect PCAPs, PLC dumps, project files, HMI logs, workstation evidence, CCTV, and relevant documentation |
| Analysis | Identify unauthorized hosts, engineering commands, program uploads, logic changes, and timeline evidence |
| Containment | Support isolation of the affected workstation, engineering pathway, or PLC network segment when safe |
| Recovery | Help engineers restore known-good PLC logic and validate that unsafe commands are no longer active |
| Monitoring | Watch for repeat traffic, new PLC uploads, unauthorized Modbus/UMAS activity, or workstation reconnection attempts |
| Reporting | Document findings, affected assets, root cause, evidence, impact, and recommendations |
| Human support | Recommend communication, victim assistance, and post-incident care for affected personnel |

The investigator's role is not only to prove what happened. The investigator also helps reduce harm by preserving reliable evidence, supporting safe recovery, and giving decision-makers clear information they can act on.

---

## 9. Conclusions

### 9.1 Attribution

| | |
|---|---|
| **Who (attacker)** | DESKTOP-RSRBUGJ — IP: 192.168.10.164 — MAC: 00:0c:29:5a:da:a3 |
| **Who (victim)** | Kristi Wayne (CEO) — DESKTOP-JKS05LO — IP: 192.168.133.137 |
| **What** | 4 malicious EcoStruxure programs uploaded to elevator PLC |
| **When** | 14:27:51 – 15:47:05, Friday June 29, 2023 |
| **How** | EcoStruxure Machine Expert → UMAS FC90 → M221 PLC (no auth) |
| **Remote compromise evidence?** | No PCAP evidence of remote compromise during the capture; local interactive use is best-supported, but host compromise cannot be fully excluded without Employee-01 host forensics |
| **Next step** | Physical identification: who was at DESKTOP-RSRBUGJ between 14:27 and 15:47? |

### 9.2 Security Failures

1. **Flat OT network** — no VLANs, no firewall between workstations and PLC
2. **No PLC authentication** — M221 UMAS accepts any connection (CVE-2020-28212)
3. **EcoStruxure on non-engineering machine** — Employee-01 had full PLC capability
4. **No IDS/IPS** — attack ran undetected for 79 minutes
5. **No program integrity checking** — malicious code ran freely after upload

### 9.3 The Four Code Changes

| # | Change | Physical Effect |
|---|---|---|
| 1 | SAME_CALL variable removed | Floor position tracking broken, elevator stuck |
| 2 | Timer: 10s/OneSecond → 5000/OneMilliSeconds | Delay changed from ~10 seconds to ~5 seconds; sub-second cycling is not proven by this change alone |
| 3 | Rung deleted from Elevator Door subtask | Consistent with unsafe door behavior; exact safety function must be proven by including the full deleted rung body |
| 4 | Project renamed 'SAFE Lab Mafia' + 'attaxk' comment | Attacker signature |
