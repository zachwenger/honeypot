# ZW Honeypot
### by Zach Wenger

I built a honeypot in Python and deployed it on AWS EC2 to capture real attack attempts from the internet. The idea was simple — put a fake server online, open up some common ports, and see what shows up. Turns out the answer is: a lot, and fast.

---

## What It Does

Opens fake listeners on ports that attackers love to target — FTP, SSH, Telnet, HTTP, HTTPS, RDP. Anyone who connects gets logged. Timestamp, IP address, port, and whatever data they sent. That's it. Simple concept, real data.

---

## Infrastructure

| Component | Details |
|---|---|
| Cloud | AWS EC2 |
| Instance | t2.micro (free tier) |
| OS | Ubuntu Server 22.04 LTS |
| Public IP | 3.93.125.65 |
| Region | US East (N. Virginia) |

![EC2 Instance](screenshots/ec2-instance.png)
![Security Group Rules](screenshots/security-group-rules.png)
![VPC Setup](screenshots/vpc-setup.png)

---

## Ports I Monitored

| Port | Service | Why it gets targeted |
|---|---|---|
| 21 | FTP | Old protocol, usually misconfigured |
| 22 | SSH | Bots brute force this constantly |
| 23 | Telnet | No encryption, default creds on most IoT devices |
| 80 | HTTP | Scanned for web vulnerabilities |
| 443 | HTTPS | SSL exploits, web app attacks |
| 3389 | RDP | Ransomware groups love hitting this |

---

## Results

Got hits within minutes of the instance going live. I didn't share the IP anywhere — bots just found it on their own by scanning the internet.

![Honeypot Running](screenshots/honeypot-running.png)
![Live Hits](screenshots/honeypot-live-hits.png)
![Log Output](screenshots/honeypot-log.png)

---

## Captured Connections

| # | Time | Port | Service | IP | Data |
|---|---|---|---|---|---|
| 1 | 2026-05-16 01:18:58 | 23 | Telnet | 177.245.231.248 | None |
| 2 | 2026-05-16 01:19:16 | 23 | Telnet | 77.236.93.44 | None |
| 3 | 2026-05-16 01:30:17 | 443 | HTTPS | 106.54.27.68 | Exploit payload |
| 4 | 2026-05-16 01:39:40 | 23 | Telnet | 37.214.9.175 | None |

---

## Threat Analysis

**Telnet hits (1, 2, 4)**

Three different IPs hit port 23 in the first 21 minutes. This is textbook automated scanning — bots sweep the entire internet looking for open Telnet ports. When they find one, they try default credentials to take over the device. This is exactly how the Mirai botnet built an army of millions of compromised IoT devices. Seeing that same pattern show up on my honeypot within minutes of going live made that feel very real.

**HTTPS exploit attempt (hit 3)**

This one was interesting. IP 106.54.27.68 connected to port 443 and immediately sent raw binary data — not a normal HTTPS handshake. The payload had non-printable characters which is a sign of a crafted exploit, probably scanning for known SSL/TLS vulnerabilities. This isn't someone manually typing — it's an automated scanner running 24/7 looking for anything it can exploit.

**What stands out**

- First hit came in under a minute of going live
- 3 out of 4 hits were Telnet — IoT botnet activity
- One attacker actually sent exploit data, not just a connection probe
- None of this was human — all automated bots

The main thing this showed me is that any exposed service gets found fast. A real Telnet server would have been getting brute forced within seconds of coming online.

---

## Run It Yourself

```bash
git clone https://github.com/zachwenger/honeypot.git
cd honeypot
sudo python3 honeypot.py
```

Needs sudo — ports under 1024 require root.

---

## Stack

- Python 3
- `socket` — port listeners
- `threading` — runs all ports at the same time
- `logging` — saves everything to a log file
- `colorama` — terminal output formatting
- AWS EC2 — cloud deployment

---

## What I Learned

Honestly the speed was the thing that got me. I spun up the instance, got everything running, and within a minute something was already knocking on port 23. The internet is constantly being scanned by automated bots and you don't have to do anything to get found.

The Mirai botnet thing clicked for me here. I'd read about how it infected millions of IoT devices through Telnet with default credentials. Seeing that exact behavior show up on my own honeypot made it go from a textbook concept to something I actually understood.

The HTTPS payload hit was the most interesting part. That wasn't just a ping — something sent crafted binary data trying to exploit whatever was running on 443. That's a real threat actor behavior pattern, not just curiosity.

Also learned a ton about AWS networking setting this up — VPCs, subnets, internet gateways, Elastic IPs, security groups. Had to configure all of it from scratch which made cloud infrastructure actually make sense.

---

*All traffic captured was unsolicited. Deployed on my own AWS instance for learning purposes.*
