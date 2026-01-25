using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CyberShieldBuddy
{
    // ═══════════════════════════════════════════════════════════════
    // ENUMS & DATA MODELS
    // ═══════════════════════════════════════════════════════════════

    public enum SecurityStatus
    {
        Safe,
        Warning,
        Unsafe
    }

    public enum ThreatLevel
    {
        Safe,
        Caution,
        Danger
    }

    public class SecurityCheckResult
    {
        public string Key { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string SafeMessage { get; set; } = "";
        public string UnsafeMessage { get; set; } = "";
        public string Tip { get; set; } = "";
        public SecurityStatus Status { get; set; }
        public string Icon { get; set; } = "\uE83D";
        public int Weight { get; set; } = 1; // For weighted scoring

        public string StatusText => Status == SecurityStatus.Safe ? "Protected" :
                                    Status == SecurityStatus.Warning ? "Review needed" : "Action needed";
        public string StatusIcon => Status == SecurityStatus.Safe ? "\uE73E" :
                                    Status == SecurityStatus.Warning ? "\uE7BA" : "\uE711";
        public string CurrentMessage => Status == SecurityStatus.Safe ? SafeMessage : UnsafeMessage;
    }

    public class UrlAnalysisResult
    {
        public ThreatLevel ThreatLevel { get; set; }
        public string Message { get; set; } = "";
        public int RiskScore { get; set; }
        public List<string> Flags { get; set; } = new List<string>();
    }

    // ═══════════════════════════════════════════════════════════════
    // SECURITY ENGINE - Premium Edition
    // ═══════════════════════════════════════════════════════════════

    public static class SecurityEngine
    {
        // --- Registry Path Constants ---
        private const string REG_TERMINAL_SERVER = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
        private const string REG_SMB_PARAMS = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        private const string REG_LSA = @"SYSTEM\CurrentControlSet\Control\Lsa";
        private const string REG_WINLOGON = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        private const string REG_CREDENTIAL_GUARD = @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";
        private const string REG_GRAPHICS_CONFIG = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration";
        private const string REG_GRAPHICS_CONNECTIVITY = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity";

        // --- P/Invoke for TCP Table ---
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tcpTableType, int reserved);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetFirmwareEnvironmentVariable(string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

        public const int AF_INET = 2;
        public const int TCP_TABLE_OWNER_PID_ALL = 5;

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        public class NetworkConnection
        {
            public string LocalAddress { get; set; } = "";
            public int LocalPort { get; set; }
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
            public string State { get; set; } = "";
            public int PID { get; set; }
            public string ProcessName { get; set; } = "";
        }

        // ═══════════════════════════════════════════════════════════════
        // WEIGHTED SCORING SYSTEM
        // ═══════════════════════════════════════════════════════════════

        // Security check weights (higher = more important)
        private static readonly Dictionary<string, int> CheckWeights = new Dictionary<string, int>
        {
            { "rdp", 20 },           // Remote Desktop - Critical
            { "smb", 20 },           // SMBv1 - Critical (WannaCry vector)
            { "guest", 15 },         // Guest Account - High
            { "lsa", 15 },           // LSA Protection - High
            { "autologon", 15 },     // Auto Logon - High
            { "credential", 15 }     // Credential Guard - High
        };

        public static int CalculateHardeningScore()
        {
            int totalWeight = 0;
            int earnedWeight = 0;

            // RDP Check (Critical - 20 points)
            totalWeight += CheckWeights["rdp"];
            if (CheckRDPStatus()) earnedWeight += CheckWeights["rdp"];

            // SMBv1 Check (Critical - 20 points)
            totalWeight += CheckWeights["smb"];
            if (CheckSMBv1()) earnedWeight += CheckWeights["smb"];

            // Guest Account (High - 15 points)
            totalWeight += CheckWeights["guest"];
            if (CheckGuestAccount()) earnedWeight += CheckWeights["guest"];

            // LSA Protection (High - 15 points)
            totalWeight += CheckWeights["lsa"];
            if (CheckLSAProtection()) earnedWeight += CheckWeights["lsa"];

            // Auto Logon (High - 15 points)
            totalWeight += CheckWeights["autologon"];
            if (CheckAutoLogon()) earnedWeight += CheckWeights["autologon"];

            // Credential Guard (High - 15 points)
            totalWeight += CheckWeights["credential"];
            if (CheckCredentialGuard()) earnedWeight += CheckWeights["credential"];

            // Calculate percentage score
            return (int)Math.Round((double)earnedWeight / totalWeight * 100);
        }

        // ═══════════════════════════════════════════════════════════════
        // HARDENING CHECKS
        // ═══════════════════════════════════════════════════════════════

        public static bool CheckRDPStatus()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("fDenyTSConnections");
                        return val != null && (int)val == 1;
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking RDP: {ex.Message}", "ERROR"); }
            return false;
        }

        public static bool CheckSMBv1()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("SMB1");
                        return val != null && (int)val == 0;
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking SMBv1: {ex.Message}", "ERROR"); }
            return false;
        }

        public static bool CheckGuestAccount()
        {
            try
            {
                using (var context = new PrincipalContext(ContextType.Machine))
                {
                    var guest = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, "Guest");
                    return guest == null || (guest.Enabled != true);
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Error checking Guest: {ex.Message}", "ERROR");
                return false;
            }
        }

        public static bool CheckLSAProtection()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("RunAsPPL");
                        return val != null && (int)val == 1;
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking LSA: {ex.Message}", "ERROR"); }
            return false;
        }

        public static bool CheckAutoLogon()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("AutoAdminLogon");
                        if (val != null && val.ToString() == "1") return false;
                        return true;
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking AutoLogon: {ex.Message}", "ERROR"); }
            return true;
        }

        public static string CheckPowerShellExecutionPolicy()
        {
            try
            {
                using (var ps = PowerShell.Create())
                {
                    ps.AddScript("Get-ExecutionPolicy");
                    var result = ps.Invoke();
                    if (ps.HadErrors) return "Unknown";
                    if (result.Count > 0)
                    {
                        return result[0].ToString();
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking PS Policy: {ex.Message}", "ERROR"); }
            return "Unknown";
        }

        public static bool CheckCredentialGuard()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("Enabled");
                        return val != null && (int)val == 1;
                    }
                }
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\LSA"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("LsaCfgFlags");
                        return val != null && ((int)val == 1 || (int)val == 2);
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking Credential Guard: {ex.Message}", "ERROR"); }
            return false;
        }

        // ═══════════════════════════════════════════════════════════════
        // SYSTEM INFO
        // ═══════════════════════════════════════════════════════════════

        public struct SystemInfo
        {
            public string OsBuild;
            public string BiosSerial;
            public string TpmStatus;
            public string BitLockerStatus;
        }

        public static SystemInfo GetSystemInfo()
        {
            var info = new SystemInfo
            {
                OsBuild = "Unknown",
                BiosSerial = "Unknown",
                TpmStatus = "Unknown",
                BitLockerStatus = "Unknown"
            };

            try
            {
                var osKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (osKey != null)
                {
                    info.OsBuild = $"{osKey.GetValue("ProductName")} ({osKey.GetValue("CurrentBuild")})";
                }

                using (var ps = PowerShell.Create())
                {
                    ps.AddScript("Get-CimInstance Win32_Bios | Select-Object -ExpandProperty SerialNumber");
                    var biosRes = ps.Invoke();
                    if (biosRes.Count > 0) info.BiosSerial = biosRes[0].ToString();
                    ps.Commands.Clear();

                    ps.AddScript("Get-Tpm | Select-Object -ExpandProperty TpmPresent");
                    var tpmRes = ps.Invoke();
                    if (tpmRes.Count > 0 && (bool)tpmRes[0].BaseObject) info.TpmStatus = "Present & Ready";
                    else info.TpmStatus = "Not Detected";
                    ps.Commands.Clear();

                    ps.AddScript("Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty ProtectionStatus");
                    var bitRes = ps.Invoke();
                    if (bitRes.Count > 0) info.BitLockerStatus = bitRes[0].ToString();
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log("Error gathering System Info: " + ex.Message, "ERROR");
            }
            return info;
        }

        public static List<SecurityCheckResult> GetAllSecurityChecks()
        {
            var results = new List<SecurityCheckResult>();

            results.Add(new SecurityCheckResult
            {
                Key = "rdp",
                Title = "Remote Desktop",
                Icon = "\uE7F4",
                SafeMessage = "Remote access is blocked - hackers can't connect to your PC remotely.",
                UnsafeMessage = "Remote access is enabled - someone could potentially access your PC from the internet.",
                Tip = "Unless you specifically need to connect from another computer, keep this disabled.",
                Status = CheckRDPStatus() ? SecurityStatus.Safe : SecurityStatus.Unsafe,
                Weight = CheckWeights["rdp"]
            });

            results.Add(new SecurityCheckResult
            {
                Key = "smb",
                Title = "Legacy File Sharing (SMBv1)",
                Icon = "\uE8B7",
                SafeMessage = "Outdated file sharing (SMBv1) is disabled - protected against ransomware attacks.",
                UnsafeMessage = "Outdated file sharing is enabled - vulnerable to WannaCry-style attacks.",
                Tip = "SMBv1 is from 1983. Modern file sharing works without it.",
                Status = CheckSMBv1() ? SecurityStatus.Safe : SecurityStatus.Unsafe,
                Weight = CheckWeights["smb"]
            });

            results.Add(new SecurityCheckResult
            {
                Key = "guest",
                Title = "Guest Account",
                Icon = "\uE77B",
                SafeMessage = "Guest account is disabled - no anonymous access to your PC.",
                UnsafeMessage = "Guest account is active - anyone could use your PC without a password.",
                Tip = "The Guest account lets people use your PC without logging in.",
                Status = CheckGuestAccount() ? SecurityStatus.Safe : SecurityStatus.Unsafe,
                Weight = CheckWeights["guest"]
            });

            results.Add(new SecurityCheckResult
            {
                Key = "lsa",
                Title = "Password Protection (LSA)",
                Icon = "\uE83D",
                SafeMessage = "Your passwords are protected with extra security.",
                UnsafeMessage = "Your saved passwords could be more vulnerable to theft.",
                Tip = "LSA Protection keeps your Windows passwords safe from hackers.",
                Status = CheckLSAProtection() ? SecurityStatus.Safe : SecurityStatus.Warning,
                Weight = CheckWeights["lsa"]
            });

            results.Add(new SecurityCheckResult
            {
                Key = "autologon",
                Title = "Auto Login",
                Icon = "\uE72E",
                SafeMessage = "You must enter your password to log in - good!",
                UnsafeMessage = "Your PC logs in automatically - anyone who turns it on gets full access.",
                Tip = "Auto-login is convenient but risky if your computer is ever stolen.",
                Status = CheckAutoLogon() ? SecurityStatus.Safe : SecurityStatus.Unsafe,
                Weight = CheckWeights["autologon"]
            });

            results.Add(new SecurityCheckResult
            {
                Key = "credential",
                Title = "Credential Guard",
                Icon = "\uE8D7",
                SafeMessage = "Advanced password protection is active.",
                UnsafeMessage = "Advanced protection is available but not enabled.",
                Tip = "This is enterprise-grade security. Nice to have but not required for home use.",
                Status = CheckCredentialGuard() ? SecurityStatus.Safe : SecurityStatus.Warning,
                Weight = CheckWeights["credential"]
            });

            return results;
        }

        public static List<string> AuditFieldCompliance()
        {
            var issues = new List<string>();
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("ScreenSaverIsSecure");
                        if (val == null || val.ToString() != "1") issues.Add("Screen Saver Password Protection is DISABLED.");

                        var timeout = key.GetValue("ScreenSaveTimeOut");
                        if (timeout != null && int.TryParse(timeout.ToString(), out int seconds))
                        {
                            if (seconds > 900) issues.Add($"Screen Lock Timeout is too long ({seconds / 60} mins). Max allowed: 15 mins.");
                        }
                        else issues.Add("Screen Lock Timeout not set.");
                    }
                }

                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("WriteProtect");
                        if (val == null || (int)val != 1) issues.Add("USB Write Protection is DISABLED.");
                    }
                    else issues.Add("USB Write Protection is DISABLED (Key missing).");
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Field Compliance Audit Error: {ex.Message}", "ERROR");
                issues.Add("Error running field compliance checks.");
            }
            return issues;
        }

        // ═══════════════════════════════════════════════════════════════
        // HARDENING ACTIONS
        // ═══════════════════════════════════════════════════════════════

        public static void ApplyHardeningBaseline()
        {
            AuditLogger.Log("Starting Hardening Baseline Application...", "INFO");

            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, RegistryValueKind.DWord);
                AuditLogger.Log("RDP Disabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to disable RDP: {ex.Message}", "ERROR"); }

            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0, RegistryValueKind.DWord);
                AuditLogger.Log("SMBv1 Disabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to disable SMBv1: {ex.Message}", "ERROR"); }

            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, RegistryValueKind.DWord);
                AuditLogger.Log("LSA Protection Enabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to enable LSA: {ex.Message}", "ERROR"); }

            try
            {
                using (var ps = PowerShell.Create())
                {
                    ps.AddScript("Disable-LocalUser -Name 'Guest'");
                    ps.Invoke();
                    if (ps.HadErrors) AuditLogger.Log("Failed to disable Guest account via PowerShell.", "ERROR");
                    else AuditLogger.Log("Guest Account Disabled.", "SUCCESS");
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to disable Guest Account: {ex.Message}", "ERROR"); }

            AuditLogger.Log("Hardening Baseline Application Complete.", "INFO");
        }

        // ═══════════════════════════════════════════════════════════════
        // NETWORK SENTRY
        // ═══════════════════════════════════════════════════════════════

        public static List<NetworkConnection> GetNetworkConnections()
        {
            var connections = new List<NetworkConnection>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    MIB_TCPTABLE_OWNER_PID table = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_PID>(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + Marshal.SizeOf(table.dwNumEntries));

                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                        connections.Add(new NetworkConnection
                        {
                            LocalAddress = IPToString(row.localAddr),
                            LocalPort = PortToHostOrder(row.localPort),
                            RemoteAddress = IPToString(row.remoteAddr),
                            RemotePort = PortToHostOrder(row.remotePort),
                            State = ((TcpState)row.state).ToString(),
                            PID = (int)row.owningPid,
                            ProcessName = GetProcessName((int)row.owningPid)
                        });

                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                    }
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Error fetching network connections: {ex.Message}", "ERROR");
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return connections;
        }

        private static string IPToString(uint ip)
        {
            return new System.Net.IPAddress(ip).ToString();
        }

        private static int PortToHostOrder(byte[] port)
        {
            return (port[0] << 8) + port[1];
        }

        private static string GetProcessName(int pid)
        {
            try
            {
                return Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        public enum TcpState
        {
            Closed = 1,
            Listen = 2,
            SynSent = 3,
            SynReceived = 4,
            Established = 5,
            FinWait1 = 6,
            FinWait2 = 7,
            CloseWait = 8,
            Closing = 9,
            LastAck = 10,
            TimeWait = 11,
            DeleteTcb = 12
        }

        // ═══════════════════════════════════════════════════════════════
        // DISPLAY FIX
        // ═══════════════════════════════════════════════════════════════

        public static void FixDisplayResolution()
        {
            AuditLogger.Log("Attempting to fix display resolution...", "INFO");

            string backupDir = Path.Combine(Path.GetTempPath(), "CyberShieldBuddy_Backups");
            Directory.CreateDirectory(backupDir);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string backupPath = Path.Combine(backupDir, $"GraphicsDrivers_{timestamp}.reg");

            try
            {
                var exportProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"export \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" \"{backupPath}\" /y",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardError = true
                    }
                };
                exportProcess.Start();
                exportProcess.WaitForExit(5000);

                if (File.Exists(backupPath))
                {
                    AuditLogger.Log($"Registry backup created: {backupPath}", "SUCCESS");
                }
                else
                {
                    AuditLogger.Log("Warning: Could not create registry backup. Proceeding with caution.", "WARN");
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Backup failed: {ex.Message}. Proceeding with caution.", "WARN");
            }

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(REG_GRAPHICS_CONFIG, true))
                {
                    if (key != null)
                    {
                        var subkeys = key.GetSubKeyNames();
                        foreach (var subkey in subkeys)
                        {
                            key.DeleteSubKeyTree(subkey);
                        }
                        AuditLogger.Log("Cleared GraphicsDrivers Configuration cache.", "SUCCESS");
                    }
                }

                using (var key = Registry.LocalMachine.OpenSubKey(REG_GRAPHICS_CONNECTIVITY, true))
                {
                    if (key != null)
                    {
                        var subkeys = key.GetSubKeyNames();
                        foreach (var subkey in subkeys)
                        {
                            key.DeleteSubKeyTree(subkey);
                        }
                        AuditLogger.Log("Cleared GraphicsDrivers Connectivity cache.", "SUCCESS");
                    }
                }

                AuditLogger.Log("Please restart your computer to apply display fixes.", "WARN");
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Error fixing display: {ex.Message}", "ERROR");
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // ADVANCED URL ANALYSIS
        // ═══════════════════════════════════════════════════════════════

        // Suspicious TLDs commonly used in phishing
        private static readonly HashSet<string> SuspiciousTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".tk", ".ml", ".ga", ".cf", ".gq",     // Free TLDs often abused
            ".xyz", ".top", ".club", ".work",      // Cheap TLDs popular with scammers
            ".click", ".link", ".download",        // Action TLDs
            ".review", ".stream", ".racing",       // Suspicious generic TLDs
            ".bid", ".win", ".loan", ".date",      // Financial/dating scam TLDs
            ".party", ".trade", ".webcam",         // Commonly abused TLDs
            ".zip", ".mov"                         // New confusing TLDs
        };

        // Major brands commonly impersonated
        private static readonly string[] ImpersonatedBrands = new[]
        {
            "paypal", "apple", "microsoft", "google", "amazon", "facebook",
            "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
            "wellsfargo", "bankofamerica", "citibank", "usbank", "capitalone",
            "americanexpress", "visa", "mastercard", "venmo", "cashapp",
            "coinbase", "binance", "metamask", "opensea", "steam", "epic",
            "roblox", "discord", "telegram", "whatsapp", "outlook", "yahoo",
            "adobe", "spotify", "uber", "airbnb", "ebay", "walmart", "target"
        };

        // Legitimate domain suffixes for brands
        private static readonly Dictionary<string, string[]> LegitDomains = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "paypal", new[] { "paypal.com", "paypal.me" } },
            { "apple", new[] { "apple.com", "icloud.com" } },
            { "microsoft", new[] { "microsoft.com", "live.com", "outlook.com", "office.com", "azure.com" } },
            { "google", new[] { "google.com", "gmail.com", "youtube.com", "googleapis.com" } },
            { "amazon", new[] { "amazon.com", "amazon.co.uk", "aws.amazon.com", "amazonws.com" } },
            { "facebook", new[] { "facebook.com", "fb.com", "meta.com" } },
            { "netflix", new[] { "netflix.com" } },
        };

        /// <summary>
        /// Advanced URL analysis with weighted risk scoring
        /// </summary>
        public static UrlAnalysisResult AnalyzeUrlAdvanced(string url)
        {
            var result = new UrlAnalysisResult
            {
                ThreatLevel = ThreatLevel.Safe,
                RiskScore = 0,
                Flags = new List<string>()
            };

            if (string.IsNullOrWhiteSpace(url))
            {
                result.Message = "Please enter a URL to analyze.";
                return result;
            }

            // Normalize URL
            string normalizedUrl = url.Trim().ToLowerInvariant();
            if (!normalizedUrl.StartsWith("http"))
            {
                normalizedUrl = "https://" + normalizedUrl;
            }

            Uri uri;
            try
            {
                uri = new Uri(normalizedUrl);
            }
            catch
            {
                result.ThreatLevel = ThreatLevel.Danger;
                result.RiskScore = 100;
                result.Message = "Invalid URL format. Cannot parse.";
                return result;
            }

            string host = uri.Host;
            string fullUrl = uri.ToString();

            // ═══════════════════════════════════════════════════════════════
            // CHECK 1: IP Address Usage (+40 risk)
            // ═══════════════════════════════════════════════════════════════
            if (Regex.IsMatch(host, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"))
            {
                result.RiskScore += 40;
                result.Flags.Add("Uses raw IP address instead of domain name");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 2: Suspicious TLD (+25 risk)
            // ═══════════════════════════════════════════════════════════════
            foreach (var tld in SuspiciousTlds)
            {
                if (host.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 25;
                    result.Flags.Add($"Uses suspicious TLD: {tld}");
                    break;
                }
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 3: Brand Impersonation Detection (+50 risk)
            // ═══════════════════════════════════════════════════════════════
            foreach (var brand in ImpersonatedBrands)
            {
                if (host.Contains(brand, StringComparison.OrdinalIgnoreCase))
                {
                    // Check if it's the legitimate domain
                    bool isLegit = false;
                    if (LegitDomains.TryGetValue(brand, out var legitDomains))
                    {
                        foreach (var legitDomain in legitDomains)
                        {
                            if (host.Equals(legitDomain, StringComparison.OrdinalIgnoreCase) ||
                                host.EndsWith("." + legitDomain, StringComparison.OrdinalIgnoreCase))
                            {
                                isLegit = true;
                                break;
                            }
                        }
                    }

                    if (!isLegit)
                    {
                        // Check for common typosquatting patterns
                        if (Regex.IsMatch(host, $@"{brand}[-_.]?(login|secure|verify|account|update|support|help)", RegexOptions.IgnoreCase) ||
                            Regex.IsMatch(host, $@"(login|secure|verify|account|update)[-_.]?{brand}", RegexOptions.IgnoreCase))
                        {
                            result.RiskScore += 50;
                            result.Flags.Add($"Possible {brand.ToUpper()} impersonation attempt");
                        }
                        else if (!host.EndsWith($".{brand}.com", StringComparison.OrdinalIgnoreCase))
                        {
                            result.RiskScore += 35;
                            result.Flags.Add($"Contains brand name '{brand}' but may not be official");
                        }
                    }
                    break;
                }
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 4: URL Encoding / Obfuscation (+30 risk)
            // ═══════════════════════════════════════════════════════════════
            int encodedCharCount = Regex.Matches(fullUrl, @"%[0-9A-Fa-f]{2}").Count;
            if (encodedCharCount > 5)
            {
                result.RiskScore += 30;
                result.Flags.Add($"Heavy URL encoding ({encodedCharCount} encoded characters)");
            }
            else if (encodedCharCount > 2)
            {
                result.RiskScore += 15;
                result.Flags.Add("Contains URL-encoded characters");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 5: @ Symbol in URL (+35 risk)
            // ═══════════════════════════════════════════════════════════════
            if (fullUrl.Contains("@") && fullUrl.IndexOf("@") < fullUrl.IndexOf("/", 8))
            {
                result.RiskScore += 35;
                result.Flags.Add("Contains @ symbol (can hide real destination)");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 6: Excessive Subdomains (+20 risk)
            // ═══════════════════════════════════════════════════════════════
            int subdomainCount = host.Split('.').Length - 2;
            if (subdomainCount > 3)
            {
                result.RiskScore += 20;
                result.Flags.Add($"Excessive subdomains ({subdomainCount} levels deep)");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 7: Suspicious Keywords in Path (+15 risk each)
            // ═══════════════════════════════════════════════════════════════
            string[] suspiciousKeywords = { "login", "signin", "verify", "secure", "update", "confirm", "account", "password", "credential", "banking", "wallet" };
            foreach (var keyword in suspiciousKeywords)
            {
                if (uri.PathAndQuery.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 15;
                    result.Flags.Add($"Suspicious keyword in path: '{keyword}'");
                    break; // Only count once
                }
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 8: Extremely Long URL (+10 risk)
            // ═══════════════════════════════════════════════════════════════
            if (fullUrl.Length > 100)
            {
                result.RiskScore += 10;
                result.Flags.Add("Unusually long URL");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 9: Non-standard Port (+15 risk)
            // ═══════════════════════════════════════════════════════════════
            if (uri.Port != 80 && uri.Port != 443 && uri.Port != -1)
            {
                result.RiskScore += 15;
                result.Flags.Add($"Non-standard port: {uri.Port}");
            }

            // ═══════════════════════════════════════════════════════════════
            // CHECK 10: HTTP instead of HTTPS (+20 risk)
            // ═══════════════════════════════════════════════════════════════
            if (uri.Scheme == "http")
            {
                result.RiskScore += 20;
                result.Flags.Add("Uses insecure HTTP (not HTTPS)");
            }

            // ═══════════════════════════════════════════════════════════════
            // DETERMINE THREAT LEVEL
            // ═══════════════════════════════════════════════════════════════
            if (result.RiskScore >= 50)
            {
                result.ThreatLevel = ThreatLevel.Danger;
            }
            else if (result.RiskScore >= 25)
            {
                result.ThreatLevel = ThreatLevel.Caution;
            }
            else
            {
                result.ThreatLevel = ThreatLevel.Safe;
            }

            // ═══════════════════════════════════════════════════════════════
            // BUILD RESULT MESSAGE
            // ═══════════════════════════════════════════════════════════════
            if (result.Flags.Count == 0)
            {
                result.Message = "No red flags detected. URL appears legitimate.\n\nAlways verify you're on the correct website before entering credentials.";
            }
            else
            {
                string severity = result.ThreatLevel == ThreatLevel.Danger ? "HIGH RISK" :
                                  result.ThreatLevel == ThreatLevel.Caution ? "CAUTION" : "LOW RISK";

                result.Message = $"{severity} (Score: {result.RiskScore}/100)\n\n";
                result.Message += string.Join("\n", result.Flags.Select(f => $"• {f}"));

                if (result.ThreatLevel == ThreatLevel.Danger)
                {
                    result.Message += "\n\nDo NOT enter any personal information on this site.";
                }
            }

            return result;
        }

        /// <summary>
        /// Legacy URL analysis method (for backwards compatibility)
        /// </summary>
        public static string AnalyzeUrl(string url)
        {
            var result = AnalyzeUrlAdvanced(url);
            return result.Message;
        }
    }
}
