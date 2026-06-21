<p align="center">
  <img src="assets/banner.png" alt="Hacking Tools Banner" width="100%" />
</p>

<h1 align="center">🛡️ Hacking Tools</h1>

<p align="center">
  <b><i>Learn Cybersecurity One Tool at a Time</i></b>
</p>

<p align="center">
  <a href="https://github.com/mitro/hacking-tools/stargazers">
    <img src="https://img.shields.io/github/stars/mitro/hacking-tools?style=for-the-badge&logo=github&logoColor=white&color=0d1117&labelColor=161b22" alt="Stars" />
  </a>
  <a href="https://github.com/mitro/hacking-tools/network/members">
    <img src="https://img.shields.io/github/forks/mitro/hacking-tools?style=for-the-badge&logo=git&logoColor=white&color=0d1117&labelColor=161b22" alt="Forks" />
  </a>
  <a href="https://github.com/mitro/hacking-tools/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/mitro/hacking-tools?style=for-the-badge&logo=opensourceinitiative&logoColor=white&color=0d1117&labelColor=161b22" alt="License" />
  </a>
  <a href="https://github.com/mitro/hacking-tools/commits/main">
    <img src="https://img.shields.io/github/last-commit/mitro/hacking-tools?style=for-the-badge&logo=git&logoColor=white&color=0d1117&labelColor=161b22" alt="Last Commit" />
  </a>
  <a href="https://github.com/mitro/hacking-tools">
    <img src="https://img.shields.io/github/repo-size/mitro/hacking-tools?style=for-the-badge&logo=databricks&logoColor=white&color=0d1117&labelColor=161b22" alt="Repo Size" />
  </a>
</p>

<p align="center">
  <a href="#-categories">Categories</a> •
  <a href="#-featured-tools">Featured Tools</a> •
  <a href="#-learning-roadmap">Roadmap</a> •
  <a href="#-contributing">Contributing</a> •
  <a href="#-support">Support</a>
</p>

---

## 📋 Table of Contents

- [Repository Overview](#-repository-overview)
- [Categories](#-categories)
  - [Information Gathering](#-information-gathering)
  - [Web Security](#-web-security)
  - [OSINT](#-osint)
  - [Network Security](#-network-security)
  - [Digital Forensics](#-digital-forensics)
  - [Reverse Engineering](#-reverse-engineering)
  - [Cloud Security](#-cloud-security)
  - [Malware Analysis](#-malware-analysis)
  - [Miscellaneous](#-miscellaneous)
- [Featured Tools](#-featured-tools)
- [Learning Roadmap](#-learning-roadmap)
- [Daily Tool Updates](#-daily-tool-updates)
- [Contributing](#-contributing)
- [Support](#-support)

---

## 🔎 Repository Overview

> **A curated, open-source encyclopedia of cybersecurity tools — organized, documented, and built for learners, professionals, and bug bounty hunters alike.**

This repository is **not** just a list of links. Every tool documented here includes:

| What You Get                | Description                                |
| :-------------------------- | :----------------------------------------- |
| 🧰 **Installation Guides**  | Step-by-step setup for every major OS      |
| 📖 **Usage Walkthroughs**   | Real-world commands with explanations      |
| 🎯 **Bug Bounty Use Cases** | Practical offensive scenarios              |
| 🛡️ **Detection & Defense**  | How blue teams spot and counter the tool   |
| 🤖 **AI Learning Notes**    | Key takeaways distilled for rapid learning |
| 🔄 **Alternatives**         | Similar tools for cross-referencing        |

Whether you're preparing for **OSCP**, hunting on **HackerOne**, or building a **SOC** — this repo has you covered.

---

## 📂 Categories

### 🔍 Information Gathering

> _Reconnaissance is the foundation of every engagement. Know your target before you strike._

Tools for footprinting, enumeration, DNS analysis, subdomain discovery, and technology fingerprinting.

| Tool                                                       | Description                                   | Docs |
| :--------------------------------------------------------- | :-------------------------------------------- | :--: |
| [Nmap](https://github.com/nmap/nmap)                       | Network discovery & security auditing         |  📄  |
| [Amass](https://github.com/owasp-amass/amass)              | Attack surface mapping & asset discovery      |  📄  |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Fast passive subdomain enumeration            |  📄  |
| [Shodan](https://github.com/achillean/shodan-python)       | Internet-connected device search engine       |  📄  |
| [Recon-ng](https://github.com/lanmaster53/recon-ng)        | Full-featured web reconnaissance framework    |  📄  |
| [theHarvester](https://github.com/laramies/theHarvester)   | E-mails, subdomains, hosts, & names harvester |  📄  |
| [Masscan](https://github.com/robertdavidgraham/masscan)    | Internet-scale port scanner                   |  📄  |
| [Censys](https://github.com/censys/censys-python)          | Search engine for internet-connected devices  |  📄  |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb)      | Next-gen web scanner & fingerprinter          |  📄  |
| [DNSRecon](https://github.com/darkoperator/dnsrecon)       | DNS enumeration & reconnaissance              |  📄  |

<details>
<summary>📌 <b>More Information Gathering Tools</b></summary>
<br>

| Tool                                              | Description                                                  | Docs |
| :------------------------------------------------ | :----------------------------------------------------------- | :--: |
| [Fierce](https://github.com/mschwager/fierce)     | DNS reconnaissance tool for locating non-contiguous IP space |  📄  |
| [Dmitry](https://github.com/jaygreig86/dmitry)    | Deepmagic information gathering tool                         |  📄  |
| [Maltego](https://github.com/paterva/maltego-trx) | Interactive data mining & link analysis                      |  📄  |

</details>

---

### 🌐 Web Security

> _The web is the largest attack surface. Master it._

Tools for web application testing, vulnerability scanning, SQL injection, XSS, directory fuzzing, and more.

| Tool                                                                     | Description                                  | Docs |
| :----------------------------------------------------------------------- | :------------------------------------------- | :--: |
| [Burp Suite](https://github.com/PortSwigger/burp-extensions-montoya-api) | Integrated platform for web security testing |  📄  |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy)                          | Open-source web app security scanner         |  📄  |
| [SQLMap](https://github.com/sqlmapproject/sqlmap)                        | Automatic SQL injection & database takeover  |  📄  |
| [Nikto](https://github.com/sullo/nikto)                                  | Web server vulnerability scanner             |  📄  |
| [Gobuster](https://github.com/OJ/gobuster)                               | Directory/file & DNS busting tool            |  📄  |
| [Ffuf](https://github.com/ffuf/ffuf)                                     | Fast web fuzzer written in Go                |  📄  |
| [Wfuzz](https://github.com/xmendez/wfuzz)                                | Web application brute-force & fuzzer         |  📄  |
| [XSStrike](https://github.com/s0md3v/XSStrike)                           | Advanced XSS detection suite                 |  📄  |
| [Nuclei](https://github.com/projectdiscovery/nuclei)                     | Fast vulnerability scanner with templates    |  📄  |
| [Dirsearch](https://github.com/maurosoria/dirsearch)                     | Web path discovery tool                      |  📄  |

<details>
<summary>📌 <b>More Web Security Tools</b></summary>
<br>

| Tool                                              | Description                                 | Docs |
| :------------------------------------------------ | :------------------------------------------ | :--: |
| [Commix](https://github.com/commixproject/commix) | Automated OS command injection exploitation |  📄  |
| [WPScan](https://github.com/wpscanteam/wpscan)    | WordPress security scanner                  |  📄  |
| [Arjun](https://github.com/s0md3v/Arjun)          | HTTP parameter discovery suite              |  📄  |

</details>

---

### 🕵️ OSINT

> _Open-source intelligence — the art of finding what's publicly available but hidden in plain sight._

Tools for social media investigation, geolocation, email tracing, image forensics, and metadata analysis.

| Tool                                                     | Description                              | Docs |
| :------------------------------------------------------- | :--------------------------------------- | :--: |
| [Maltego](https://github.com/paterva/maltego-trx)        | Visual link analysis & data mining       |  📄  |
| [SpiderFoot](https://github.com/smicallef/spiderfoot)    | Automated OSINT collection               |  📄  |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across social networks   |  📄  |
| [Photon](https://github.com/s0md3v/Photon)               | Fast web crawler designed for OSINT      |  📄  |
| [ExifTool](https://github.com/exiftool/exiftool)         | Read & write metadata in files           |  📄  |
| [Metagoofil](https://github.com/opsdisk/metagoofil)      | Metadata extractor from public documents |  📄  |
| [Twint](https://github.com/twintproject/twint)           | Advanced Twitter scraping & OSINT        |  📄  |
| [Holehe](https://github.com/megadose/holehe)             | Check if an email is registered on sites |  📄  |
| [GHunt](https://github.com/mxrch/GHunt)                  | Google account investigation tool        |  📄  |
| [Recon-ng](https://github.com/lanmaster53/recon-ng)      | Web reconnaissance framework             |  📄  |

---

### 🌐 Network Security

> _Control the network, control everything._

Tools for packet analysis, MITM attacks, wireless hacking, traffic manipulation, and protocol exploitation.

| Tool                                                         | Description                          | Docs |
| :----------------------------------------------------------- | :----------------------------------- | :--: |
| [Wireshark](https://github.com/wireshark/wireshark)          | Network protocol analyzer            |  📄  |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Penetration testing framework        |  📄  |
| [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)    | Wireless network security toolset    |  📄  |
| [Ettercap](https://github.com/Ettercap/ettercap)             | Comprehensive MITM attack suite      |  📄  |
| [Responder](https://github.com/lgandx/Responder)             | LLMNR, NBT-NS & MDNS poisoner        |  📄  |
| [Bettercap](https://github.com/bettercap/bettercap)          | Swiss army knife for network attacks |  📄  |
| [Hping3](https://github.com/antirez/hping)                   | Network tool for packet crafting     |  📄  |
| [Netcat](https://github.com/diegocr/netcat)                  | TCP/UDP networking swiss army knife  |  📄  |
| [Tcpdump](https://github.com/the-tcpdump-group/tcpdump)      | Command-line packet analyzer         |  📄  |
| [Scapy](https://github.com/secdev/scapy)                     | Packet manipulation library & tool   |  📄  |

---

### 🔬 Digital Forensics

> _Every action leaves a trace. Learn to find it._

Tools for disk imaging, memory analysis, timeline reconstruction, file recovery, and evidence acquisition.

| Tool                                                              | Description                             | Docs |
| :---------------------------------------------------------------- | :-------------------------------------- | :--: |
| [Autopsy](https://github.com/sleuthkit/autopsy)                   | Digital forensics platform              |  📄  |
| [Volatility](https://github.com/volatilityfoundation/volatility3) | Advanced memory forensics framework     |  📄  |
| [Sleuth Kit](https://github.com/sleuthkit/sleuthkit)              | File system & volume forensic analysis  |  📄  |
| [FTK Imager](https://github.com/exterro/ftk-imager)               | Forensic data imaging tool              |  📄  |
| [Binwalk](https://github.com/ReFirmLabs/binwalk)                  | Firmware analysis & extraction          |  📄  |
| [Foremost](https://github.com/korczis/foremost)                   | File carving & recovery tool            |  📄  |
| [Bulk Extractor](https://github.com/simsong/bulk_extractor)       | High-performance digital forensics tool |  📄  |
| [YARA](https://github.com/VirusTotal/yara)                        | Pattern matching for malware research   |  📄  |
| [Plaso](https://github.com/log2timeline/plaso)                    | Super timeline creation engine          |  📄  |
| [Hashcat](https://github.com/hashcat/hashcat)                     | Advanced password recovery              |  📄  |

---

### ⚙️ Reverse Engineering

> _Understand the machine. Tear it apart. Rebuild it._

Tools for binary analysis, disassembly, decompilation, debugging, and exploit development.

| Tool                                                        | Description                                   | Docs |
| :---------------------------------------------------------- | :-------------------------------------------- | :--: |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra)  | NSA's software reverse engineering suite      |  📄  |
| [IDA Pro](https://github.com/idapython/src)                 | Interactive disassembler & debugger           |  📄  |
| [Radare2](https://github.com/radareorg/radare2)             | UNIX-like reverse engineering framework       |  📄  |
| [GDB](https://github.com/bminor/binutils-gdb)               | GNU project debugger                          |  📄  |
| [x64dbg](https://github.com/x64dbg/x64dbg)                  | Open-source x64/x32 debugger for Windows      |  📄  |
| [OllyDbg](https://github.com/x64dbg/OllyDbg)                | 32-bit assembler-level debugger               |  📄  |
| [Binary Ninja](https://github.com/Vector35/binaryninja-api) | Reverse engineering platform                  |  📄  |
| [Frida](https://github.com/frida/frida)                     | Dynamic instrumentation toolkit               |  📄  |
| [Angr](https://github.com/angr/angr)                        | Binary analysis platform (symbolic execution) |  📄  |
| [Capstone](https://github.com/capstone-engine/capstone)     | Lightweight multi-arch disassembly framework  |  📄  |

---

### ☁️ Cloud Security

> _The cloud is someone else's computer — and it needs to be secured._

Tools for AWS/Azure/GCP security auditing, misconfiguration detection, container security, and IAM analysis.

| Tool                                                       | Description                                   | Docs |
| :--------------------------------------------------------- | :-------------------------------------------- | :--: |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite)       | Multi-cloud security auditing tool            |  📄  |
| [Prowler](https://github.com/prowler-cloud/prowler)        | AWS & Azure security assessment               |  📄  |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu)          | AWS exploitation framework                    |  📄  |
| [CloudSploit](https://github.com/aquasecurity/cloudsploit) | Cloud security configuration monitoring       |  📄  |
| [Trivy](https://github.com/aquasecurity/trivy)             | Comprehensive security scanner for containers |  📄  |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | Kubernetes penetration testing tool           |  📄  |
| [Checkov](https://github.com/bridgecrewio/checkov)         | Static analysis for IaC security              |  📄  |
| [CloudMapper](https://github.com/duo-labs/cloudmapper)     | AWS environment visualization & auditing      |  📄  |
| [Falco](https://github.com/falcosecurity/falco)            | Cloud-native runtime security                 |  📄  |
| [Steampipe](https://github.com/turbot/steampipe)           | Universal cloud API query interface           |  📄  |

---

### 🦠 Malware Analysis

> _Know your enemy. Dissect the threat._

Tools for static analysis, dynamic analysis, sandboxing, unpacking, and threat intelligence.

| Tool                                                                 | Description                                   | Docs |
| :------------------------------------------------------------------- | :-------------------------------------------- | :--: |
| [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo)            | Automated malware analysis system             |  📄  |
| [YARA](https://github.com/VirusTotal/yara)                           | Pattern matching for malware researchers      |  📄  |
| [PE-bear](https://github.com/hasherezade/pe-bear)                    | Portable Executable reversing tool            |  📄  |
| [Detect It Easy](https://github.com/horsicq/Detect-It-Easy)          | Packer/compiler/linker detection              |  📄  |
| [FLOSS](https://github.com/mandiant/flare-floss)                     | FireEye Labs obfuscated string solver         |  📄  |
| [Remnux](https://github.com/REMnux/remnux-cli)                       | Linux toolkit for reverse-engineering malware |  📄  |
| [Process Monitor](https://github.com/Sysinternals/ProcMon-for-Linux) | Advanced Windows system monitoring            |  📄  |
| [Pestudio](https://github.com/nicehash/pestudio)                     | Static malware initial assessment             |  📄  |
| [Any.Run](https://any.run/)                                          | Interactive online malware sandbox            |  📄  |
| [Strings](https://github.com/glmcdona/strings2)                      | Extract printable strings from binaries       |  📄  |

---

### 🧩 Miscellaneous

> _Essential utilities that don't fit one category but are indispensable in every toolkit._

| Tool                                                                        | Description                                        | Docs |
| :-------------------------------------------------------------------------- | :------------------------------------------------- | :--: |
| [CyberChef](https://github.com/gchq/CyberChef)                              | The cyber swiss army knife (data ops)              |  📄  |
| [John the Ripper](https://github.com/openwall/john)                         | Password cracker                                   |  📄  |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra)                         | Network logon brute-force tool                     |  📄  |
| [Hashcat](https://github.com/hashcat/hashcat)                               | Advanced GPU-based password recovery               |  📄  |
| [Impacket](https://github.com/fortra/impacket)                              | Collection of Python classes for network protocols |  📄  |
| [SecLists](https://github.com/danielmiessler/SecLists)                      | Security tester's companion wordlists              |  📄  |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Useful payloads & bypass techniques                |  📄  |
| [Proxychains](https://github.com/haad/proxychains)                          | Redirect connections through proxy servers         |  📄  |
| [Tor](https://github.com/torproject/tor)                                    | Anonymous communication network                    |  📄  |
| [SearchSploit](https://github.com/offensive-security/exploitdb)             | CLI search for Exploit-DB                          |  📄  |

---

## ⭐ Featured Tools

<table>
  <tr>
    <td align="center" width="150">
      <br>
      <b>🔍 Nmap</b>
      <br>
      <sub>Network Scanner</sub>
      <br>
      <a href="https://github.com/nmap/nmap">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🌐 Burp Suite</b>
      <br>
      <sub>Web Proxy</sub>
      <br>
      <a href="https://github.com/PortSwigger/burp-extensions-montoya-api">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>💉 SQLMap</b>
      <br>
      <sub>SQL Injection</sub>
      <br>
      <a href="https://github.com/sqlmapproject/sqlmap">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🛡️ Metasploit</b>
      <br>
      <sub>Exploit Framework</sub>
      <br>
      <a href="https://github.com/rapid7/metasploit-framework">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🔬 Ghidra</b>
      <br>
      <sub>Reverse Engineering</sub>
      <br>
      <a href="https://github.com/NationalSecurityAgency/ghidra">Learn →</a>
    </td>
  </tr>
  <tr>
    <td align="center" width="150">
      <br>
      <b>📡 Wireshark</b>
      <br>
      <sub>Packet Analysis</sub>
      <br>
      <a href="https://github.com/wireshark/wireshark">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🕵️ Sherlock</b>
      <br>
      <sub>OSINT Usernames</sub>
      <br>
      <a href="https://github.com/sherlock-project/sherlock">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🚀 Nuclei</b>
      <br>
      <sub>Vuln Scanner</sub>
      <br>
      <a href="https://github.com/projectdiscovery/nuclei">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>☁️ Prowler</b>
      <br>
      <sub>Cloud Security</sub>
      <br>
      <a href="https://github.com/prowler-cloud/prowler">Learn →</a>
    </td>
    <td align="center" width="150">
      <br>
      <b>🧠 Volatility</b>
      <br>
      <sub>Memory Forensics</sub>
      <br>
      <a href="https://github.com/volatilityfoundation/volatility3">Learn →</a>
    </td>
  </tr>
</table>

---

## 🗺️ Learning Roadmap

> Follow this path to go from beginner to advanced. Each phase builds on the last.

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   Phase 1 ─── FOUNDATIONS                                        ║
║   ├── 🖥️  Linux Fundamentals & CLI Mastery                      ║
║   ├── 🌐  Networking (TCP/IP, DNS, HTTP, TLS)                   ║
║   ├── 🐍  Scripting (Python / Bash)                              ║
║   └── 🔐  Security Concepts (CIA Triad, OWASP Top 10)           ║
║                          │                                       ║
║                          ▼                                       ║
║   Phase 2 ─── RECONNAISSANCE & OSINT                             ║
║   ├── 🔍  Nmap, Masscan, Shodan                                 ║
║   ├── 🌍  Amass, Subfinder, theHarvester                        ║
║   ├── 🕵️  Sherlock, SpiderFoot, Maltego                         ║
║   └── 📡  Wireshark, Tcpdump                                    ║
║                          │                                       ║
║                          ▼                                       ║
║   Phase 3 ─── WEB APPLICATION SECURITY                           ║
║   ├── 🔓  Burp Suite, OWASP ZAP                                 ║
║   ├── 💉  SQLMap, XSStrike, Commix                              ║
║   ├── 📂  Gobuster, Ffuf, Dirsearch                             ║
║   └── 🚀  Nuclei, Nikto, WPScan                                 ║
║                          │                                       ║
║                          ▼                                       ║
║   Phase 4 ─── EXPLOITATION & POST-EXPLOITATION                   ║
║   ├── 🛡️  Metasploit Framework                                  ║
║   ├── 🔑  Hashcat, John the Ripper, Hydra                       ║
║   ├── 🔗  Impacket, Responder, Bettercap                        ║
║   └── ⚔️  Custom Exploit Development                             ║
║                          │                                       ║
║                          ▼                                       ║
║   Phase 5 ─── ADVANCED SPECIALIZATION                            ║
║   ├── ⚙️  Ghidra, Radare2, Frida (Reverse Engineering)          ║
║   ├── 🦠  Cuckoo, YARA, Remnux (Malware Analysis)              ║
║   ├── ☁️  Prowler, ScoutSuite, Pacu (Cloud Security)            ║
║   └── 🔬  Volatility, Autopsy, Plaso (Digital Forensics)        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### 🎯 Certification Alignment

| Phase     | Recommended Certifications                     |
| :-------- | :--------------------------------------------- |
| Phase 1–2 | CompTIA Security+, CEH                         |
| Phase 3   | eWPT, BSCP (Burp Suite Certified Practitioner) |
| Phase 4   | OSCP, CRTP                                     |
| Phase 5   | GREM, GCFA, CCSP, OSED                         |

---

## 📅 Daily Tool Updates

> A new tool is documented every day. Track progress below.

<!--
  UPDATE THIS SECTION as you add new tools.
  Format: | Date | Tool | Category | Status |
-->

| Date       | Tool       | Category              | Status |
| :--------- | :--------- | :-------------------- | :----: |
| 2026-06-03 | Nmap       | Information Gathering |   ✅   |
| 2026-06-04 | Burp Suite | Web Security          |   🔜   |
| 2026-06-05 | SQLMap     | Web Security          |   🔜   |
| 2026-06-06 | Sherlock   | OSINT                 |   🔜   |
| 2026-06-07 | Wireshark  | Network Security      |   🔜   |
| 2026-06-08 | Metasploit | Network Security      |   🔜   |
| 2026-06-09 | Ghidra     | Reverse Engineering   |   🔜   |

<p align="center">
  <i>✅ Complete &nbsp;│&nbsp; 🔜 Upcoming &nbsp;│&nbsp; 📝 In Progress</i>
</p>

---

## 🤝 Contributing

Contributions are what make the open-source community an incredible place to learn and grow. **All contributions are welcome!**

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch
   ```bash
   git checkout -b tool/your-tool-name
   ```
3. **Use the template** — copy [`templates/tool-template.md`](templates/tool-template.md) and fill it out
4. **Place your file** in the correct category folder under `tools/`
5. **Update** `README.md` to add your tool to the category table
6. **Commit** your changes
   ```bash
   git commit -m "docs: add [tool-name] to [category]"
   ```
7. **Push** and open a **Pull Request**

### Contribution Guidelines

| Rule                         | Description                                                                |
| :--------------------------- | :------------------------------------------------------------------------- |
| 📝 **Use the template**      | Every tool page must follow [tool-template.md](templates/tool-template.md) |
| ✅ **Legal tools only**      | Document tools for authorized security testing only                        |
| 🎯 **Quality over quantity** | Thorough documentation beats placeholder pages                             |
| 🔍 **Verify commands**       | Test every command before documenting it                                   |
| 📚 **Cite sources**          | Link to official docs and references                                       |

> **⚠️ Disclaimer:** This repository is for **educational and authorized security testing purposes only.** Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

## 💖 Support

If this project helps your cybersecurity journey, consider supporting it:

<p align="center">
  <a href="https://github.com/mitro/hacking-tools/stargazers">
    <img src="https://img.shields.io/badge/⭐_Star_This_Repo-0d1117?style=for-the-badge&logo=github&logoColor=white" alt="Star This Repo" />
  </a>
  &nbsp;
  <a href="https://github.com/mitro/hacking-tools/fork">
    <img src="https://img.shields.io/badge/🍴_Fork_&_Contribute-0d1117?style=for-the-badge&logo=git&logoColor=white" alt="Fork & Contribute" />
  </a>
  &nbsp;
  <a href="https://github.com/mitro/hacking-tools/issues">
    <img src="https://img.shields.io/badge/🐛_Report_Issues-0d1117?style=for-the-badge&logo=github&logoColor=white" alt="Report Issues" />
  </a>
</p>

### 🌟 Share the Knowledge

```
If you find this useful, share it with someone who's learning cybersecurity.
Knowledge grows when shared. 🚀
```

---

<p align="center">
  <img src="https://img.shields.io/badge/Built_with-❤️_&_☕-0d1117?style=flat-square" alt="Built with Love" />
  <br><br>
  <b>Made for the cybersecurity community, by the cybersecurity community.</b>
  <br>
  <sub>© 2026 Hacking Tools • Educational Use Only • <a href="https://github.com/mitro/hacking-tools/blob/main/LICENSE">MIT License</a></sub>
  <br><br>
  <a href="#️-hacking-tools">⬆ Back to Top</a>
</p>
