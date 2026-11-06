# 💻 Laptop Intelligence Collector

> A comprehensive Windows system audit tool that collects hardware, network, security, and diagnostic information — all locally, with zero data transmission.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-Open%20Source-green)

---

## 📥 Download

<a href="https://github.com/ayushdas27/Laptop-Intelligence-Collector/releases/latest/download/Laptop_Intelligence_Collector_v1.0.zip">
  <img src="https://img.shields.io/badge/⬇_Download_Setup-v1.0-brightgreen?style=for-the-badge&logo=windows" alt="Download Setup" />
</a>

> **Steps:** Download the zip → Extract → Open terminal in folder → Run `python main.py`

---

## 📋 Overview

**Laptop Intelligence Collector** is a Python-based tool that automatically gathers detailed system information from a Windows laptop and compiles it into three output formats:

- 🌐 **Interactive HTML Dashboard** — searchable, styled report
- 📄 **Plain Text Report** — raw tabular data
- 🗄️ **SQLite Database** — historical audit tracking across multiple runs

## 🔍 What It Collects

| Category | Details |
|---|---|
| **Device Info** | Hostname, OS version, architecture, manufacturer, model, BIOS, boot time |
| **Network** | Public/private IP, network adapters, IP configuration |
| **DNS** | Configured DNS servers, recent DNS cache records |
| **Connections** | Active TCP & UDP endpoints (netstat) |
| **Hardware** | CPU model/cores/threads, RAM, GPU, storage devices |
| **Apps & Services** | Top 20 processes by CPU, running services, startup applications |
| **Security** | Firewall status, Windows Defender status, login events, USB history |
| **Wi-Fi & Diagnostics** | Current Wi-Fi connection, saved profiles, ping & HTTPS resolution tests |

## 🚀 Quick Start

### Requirements
- Windows 10 or Windows 11
- Python 3.x installed and added to system PATH

### Usage

1. **Clone or download** this repository
2. Open a terminal in the project folder
3. Run:
   ```
   python main.py
   ```
4. Check the generated `Output/` folder for your reports

### Output Files

```
Output/
├── laptop_report.html    # Interactive web dashboard
├── laptop_report.txt     # Plain text report
└── laptop_audit.db       # SQLite database (historical)
```

## 🔒 Security & Privacy

- ✅ **All data is processed locally** — nothing is transmitted to external servers
- ✅ **Read-only operations** — the script never modifies Windows settings or disables security features
- ✅ **No sensitive data collected** — Wi-Fi passwords, private keys, and browser credentials are **never** touched
- ℹ️ Some security events (e.g., login history) require Administrator privileges and will show a notice if run as a standard user

## 🔎 Cross-Verification Resources

After running the tool, you can verify your results using these online resources:

| Site | What It Checks |
|---|---|
| [ipinfo.io](https://ipinfo.io) | Public IP, ISP, geolocation |
| [dnsleaktest.com](https://dnsleaktest.com) | DNS server routing |
| [deviceinfo.me](https://deviceinfo.me) | OS, CPU, RAM exposed by browser |
| [canyouseeme.org](https://canyouseeme.org) | Firewall & open port exposure |
| [browserleaks.com](https://browserleaks.com) | WebRTC, private IP, media devices |
| [coveryourtracks.eff.org](https://coveryourtracks.eff.org) | Browser fingerprint uniqueness |

## 📁 Project Structure

```
├── main.py            # Main collection & report generation script
├── README.md          # This file
├── README.txt         # Original readme notes
├── H0W TO USE.txt     # Quick-start usage guide
└── Output/            # Generated after running (not tracked in git)
```

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## 📝 License

This project is open source. Feel free to use, modify, and distribute.
