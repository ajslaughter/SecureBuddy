<div align="center">

# 🛡️ CyberShield Buddy

### Your Personal Security Command Center for Windows

[![Download Now](https://img.shields.io/badge/⬇_Download-CyberShield_Buddy-06b6d4?style=for-the-badge&labelColor=030712)](https://github.com/ajslaughter/WinSysAuto/releases/latest/download/CyberShieldBuddy.exe)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=flat-square&logo=windows)](https://github.com/ajslaughter/WinSysAuto)
[![License](https://img.shields.io/badge/License-Free-10b981?style=flat-square)](LICENSE)

---

**Stop wondering if your PC is secure.** CyberShield Buddy gives you instant visibility into your system's security posture and fixes vulnerabilities with one click.

[Download Now](#installation) • [Features](#features) • [Screenshots](#screenshots) • [FAQ](#faq)

</div>

---

## Why CyberShield Buddy?

| ❌ **Without CyberShield** | ✅ **With CyberShield** |
|---------------------------|------------------------|
| Digging through Windows settings | Real-time security dashboard |
| Googling "is my PC secure?" | Clear threat level score |
| Wondering about suspicious links | Instant phishing detection |
| Complex security configurations | One-click hardening |

---

## ✨ Features

### 🎯 Threat Level Dashboard
Get an instant security score from 0-100. The animated radar visualization shows your protection level at a glance:
- **Green (85-100)**: Excellent protection
- **Amber (60-84)**: Room for improvement
- **Red (0-59)**: Action required

### 🔒 One-Click Hardening
Press **Harden System** to automatically apply industry-recommended security settings:

| Setting | What It Does |
|---------|-------------|
| **Disable RDP** | Blocks remote desktop access (prevents remote attacks) |
| **Block SMBv1** | Disables outdated file sharing (prevents WannaCry-style ransomware) |
| **Enable LSA Protection** | Protects stored passwords from theft |
| **Disable Guest Account** | Prevents anonymous access to your PC |

### 🔍 Threat Scanner
Paste any suspicious URL to instantly analyze it for:
- ⚠️ Raw IP addresses (phishing indicator)
- ⚠️ Suspicious domain extensions (.xyz, .top, etc.)
- ⚠️ Brand impersonation attempts
- ⚠️ URL manipulation techniques
- ⚠️ Excessive subdomains
- ⚠️ Encoded/hidden characters

### 🌐 Network Monitor
See every application connected to the internet from your PC:
- Real-time connection list
- Process names and remote addresses
- Connection states
- Spot unfamiliar connections instantly

### 🖥️ Display Recovery
Experiencing monitor issues? One click resets your display configuration cache:
- Fixes resolution problems
- Resolves multi-monitor glitches
- Creates automatic backup
- Safe and reversible

---

## 📸 Screenshots

<div align="center">

| Threat Dashboard | Security Findings |
|-----------------|-------------------|
| *Animated radar with real-time score* | *Detailed security check results* |

| Threat Scanner | Network Monitor |
|---------------|-----------------|
| *Instant URL analysis* | *Live connection tracking* |

</div>

*Screenshots coming soon*

---

## 🚀 Installation

### Quick Start (Recommended)
1. **[Download CyberShieldBuddy.exe](https://github.com/ajslaughter/WinSysAuto/releases/latest/download/CyberShieldBuddy.exe)**
2. **Run the EXE** - Click "More info" → "Run anyway" if Windows SmartScreen appears
3. **Click "Yes"** on the admin prompt
4. **Analyze your system!**

> 💡 **Portable App**: No installation required. Run from anywhere, even a USB drive.

### System Requirements
- Windows 10 or Windows 11 (64-bit)
- Administrator privileges (for security scans)
- ~50MB disk space

---

## 🛡️ Security Philosophy

CyberShield Buddy follows these principles:

1. **Transparency**: Every change is logged and explained
2. **Reversibility**: All security settings can be undone
3. **Privacy**: No data leaves your PC — ever
4. **Minimal Footprint**: Single portable executable, no services installed

---

## ❓ FAQ

<details>
<summary><strong>Is this safe to use?</strong></summary>

Yes. CyberShield Buddy only applies well-documented, Microsoft-recommended security settings. All changes are logged and can be reversed. The app requires admin privileges to make system changes, but never connects to the internet or sends any data.
</details>

<details>
<summary><strong>Will this slow down my computer?</strong></summary>

No. The security settings improve protection without affecting performance. CyberShield Buddy itself is a lightweight portable app that only runs when you open it.
</details>

<details>
<summary><strong>What if something breaks?</strong></summary>

All security changes are standard Windows settings. The Display Recovery tool creates automatic backups. If you experience issues, you can reverse changes through Windows Settings or by restoring from the backup.
</details>

<details>
<summary><strong>Do I need technical knowledge?</strong></summary>

Not at all! That's the whole point. CyberShield Buddy translates complex security concepts into plain English and handles the technical details for you.
</details>

<details>
<summary><strong>Is this a replacement for antivirus?</strong></summary>

No. CyberShield Buddy complements your antivirus by hardening your system configuration. It checks settings that most antivirus software doesn't touch. Keep Windows Defender or your preferred antivirus enabled.
</details>

<details>
<summary><strong>Why does Windows SmartScreen show a warning?</strong></summary>

SmartScreen warns about apps it hasn't seen before. As more people download CyberShield Buddy, this warning will disappear. The app is safe — you can verify by checking the source code in this repository.
</details>

---

## 🔧 For Developers

### Building from Source

```powershell
# Clone the repository
git clone https://github.com/ajslaughter/WinSysAuto.git
cd WinSysAuto

# Build the application
dotnet publish CyberShieldBuddy.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Output: ./publish/CyberShieldBuddy.exe
```

### Tech Stack
- .NET 8.0 (Windows)
- WPF with ModernWpfUI
- Single-file deployment
- No external dependencies at runtime

---

## 📝 Changelog

### v1.0
- Initial release
- Threat Level Dashboard with animated radar
- 6 security checks (RDP, SMBv1, Guest, LSA, AutoLogon, Credential Guard)
- One-click hardening
- URL Threat Scanner
- Network Monitor
- Display Recovery tool

---

## 🤝 Contributing

Found a bug? Have a feature idea? Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📜 License

Free for personal use. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ to help everyone stay safe online**

[⬆ Back to top](#-cybershield-buddy)

</div>
