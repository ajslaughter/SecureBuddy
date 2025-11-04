# Lab Overview

The WinSysAuto module targets the **lab.local** Active Directory forest hosted on
**DC01.lab.local** (Windows Server 2022). Key design assumptions:

- **Domain & Forest**: lab.local (single domain forest)
- **Core Server Roles on DC01**: Active Directory Domain Services, DNS, DHCP, File Services
- **Networking**: 192.168.200.0/24 with gateway 192.168.200.2 (VMware NAT)
- **DNS Forwarders**: 1.1.1.1 and 8.8.8.8 (loopback configured on DC)
- **DHCP Scope**: 192.168.200.21 – 192.168.200.200 with router 192.168.200.2, DNS 192.168.200.10
- **Organisational Units**:
  - OU=Departments (root)
    - OU=IT
    - OU=Sales
    - OU=HR
    - OU=Finance
- **Groups**: Global security group **AllStaff** plus optional SG_<Department> groups
- **File Services**: `\\DC01\CompanyFiles` mapped to `C:\Shares\CompanyFiles`
  - NTFS: Domain Admins (Full Control), AllStaff (Read)
  - Share: Domain Admins (Full), AllStaff (Change)
- **Existing GPO**: “Auto Windows Updates” linked to OU=Departments

The module is idempotent and designed to detect current state before applying change.
