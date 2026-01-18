using System;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;

namespace CyberShieldBuddy
{
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

        public const int AF_INET = 2;    // IPv4
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

        // --- Hardening Checks ---

        public static bool CheckRDPStatus()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("fDenyTSConnections");
                        return val != null && (int)val == 1; // 1 means RDP is disabled (secure)
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
                        return val != null && (int)val == 0; // 0 means SMB1 disabled
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking SMBv1: {ex.Message}", "ERROR"); }
            return false; // Assume unsafe if check fails
        }

        public static bool CheckGuestAccount()
        {
            // Replaced PowerShell with DirectoryServices for ~50MB memory savings and faster execution
            try
            {
                using (var context = new PrincipalContext(ContextType.Machine))
                {
                    var guest = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, "Guest");
                    // If guest is null, it doesn't exist (Secure). If Enabled is null/false, it is Secure.
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
                        // If it's "1", AutoLogon is ON (Unsafe). We want it to be 0 or null.
                        if (val != null && val.ToString() == "1") return false;
                        return true;
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking AutoLogon: {ex.Message}", "ERROR"); }
            return true; // Default to safe if key missing
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
                // Also check LSA Iso
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\LSA"))
                {
                     if (key != null)
                    {
                        var val = key.GetValue("LsaCfgFlags");
                        // 1 or 2 enables LSA ISO
                        return val != null && ((int)val == 1 || (int)val == 2);
                    }
                }
            }
            catch (Exception ex) { AuditLogger.Log($"Error checking Credential Guard: {ex.Message}", "ERROR"); }
            return false;
        }

        // --- System Info Gathering ---

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
                 // OS Build
                var osKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (osKey != null)
                {
                    info.OsBuild = $"{osKey.GetValue("ProductName")} ({osKey.GetValue("CurrentBuild")})";
                }

                using (var ps = PowerShell.Create())
                {
                     // BIOS Serial
                    ps.AddScript("Get-CimInstance Win32_Bios | Select-Object -ExpandProperty SerialNumber");
                    var biosRes = ps.Invoke();
                    if (biosRes.Count > 0) info.BiosSerial = biosRes[0].ToString();
                    ps.Commands.Clear();

                    // TPM Status
                    ps.AddScript("Get-Tpm | Select-Object -ExpandProperty TpmPresent");
                    var tpmRes = ps.Invoke();
                    if (tpmRes.Count > 0 && (bool)tpmRes[0].BaseObject) info.TpmStatus = "Present & Ready";
                    else info.TpmStatus = "Not Detected";
                    ps.Commands.Clear();

                    // BitLocker
                    ps.AddScript("Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty ProtectionStatus");
                    var bitRes = ps.Invoke();
                    if (bitRes.Count > 0) info.BitLockerStatus = bitRes[0].ToString(); // Off or On
                }
            }
            catch (Exception ex)
            {
                AuditLogger.Log("Error gathering System Info: " + ex.Message, "ERROR");
            }
            return info;
        }
        
        public static int CalculateHardeningScore()
        {
            int score = 0;
            int totalChecks = 6; 

            if (CheckRDPStatus()) score++;
            if (CheckSMBv1()) score++;
            if (CheckGuestAccount()) score++;
            if (CheckLSAProtection()) score++;
            if (CheckAutoLogon()) score++;
            if (CheckCredentialGuard()) score++;

            return (int)((double)score / totalChecks * 100);
        }

        public static List<string> AuditFieldCompliance()
        {
            var issues = new List<string>();
            try
            {
                // check 1: Screen Saver Password Enable
                using (var key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop"))
                {
                    if (key != null)
                    {
                        var val = key.GetValue("ScreenSaverIsSecure");
                         if (val == null || val.ToString() != "1") issues.Add("Screen Saver Password Protection is DISABLED.");
                         
                         var timeout = key.GetValue("ScreenSaveTimeOut"); // Seconds
                         if (timeout != null && int.TryParse(timeout.ToString(), out int seconds))
                         {
                             if (seconds > 900) issues.Add($"Screen Lock Timeout is too long ({seconds/60} mins). Max allowed: 15 mins.");
                         }
                         else issues.Add("Screen Lock Timeout not set.");
                    }
                }

                // check 2: Removable Storage Write Protect (Machine)
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

        // --- Hardening Actions ---

        public static void ApplyHardeningBaseline()
        {
            AuditLogger.Log("Starting Hardening Baseline Application...", "INFO");

            // Disable RDP
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1, RegistryValueKind.DWord);
                AuditLogger.Log("RDP Disabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to disable RDP: {ex.Message}", "ERROR"); }

            // Disable SMBv1
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0, RegistryValueKind.DWord);
                AuditLogger.Log("SMBv1 Disabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to disable SMBv1: {ex.Message}", "ERROR"); }

            // Enable LSA Protection
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, RegistryValueKind.DWord);
                AuditLogger.Log("LSA Protection Enabled.", "SUCCESS");
            }
            catch (Exception ex) { AuditLogger.Log($"Failed to enable LSA: {ex.Message}", "ERROR"); }

            // Disable Guest Account
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

        // --- Network Sentry ---

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

        // --- Resolution Emergency ---

        public static void FixDisplayResolution()
        {
            AuditLogger.Log("Attempting to fix display resolution...", "INFO");

            // SAFETY: Backup registry keys before destructive operations
            string backupDir = Path.Combine(Path.GetTempPath(), "CyberShieldBuddy_Backups");
            Directory.CreateDirectory(backupDir);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string backupPath = Path.Combine(backupDir, $"GraphicsDrivers_{timestamp}.reg");

            try
            {
                // Export registry keys using reg.exe for reliable backup
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

            // Proceed with registry deletion
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



        // --- Basic URL Syntax Checker ---
        // NOTE: This is NOT a phishing detector. It only checks URL format.
        // For actual phishing detection, integrate Google Safe Browsing or VirusTotal API.
        public static string AnalyzeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "Please enter a URL.";

            // Basic format checks
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return "⚠️ Format Issue: URL does not start with http/https.";

            // Check for IP address usage
            if (System.Text.RegularExpressions.Regex.IsMatch(url, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                return "⚠️ Caution: URL contains raw IP address (common in phishing).";

            // Suspicious characters
            if (url.Contains("@"))
                return "⚠️ Caution: URL contains '@' symbol (common in credential harvesting).";

            // Length check
            if (url.Length > 75)
                return "ℹ️ Note: Unusually long URL. Verify the domain carefully.";

            return "✓ No obvious format issues detected.\n⚠️ This does NOT guarantee the site is safe. Always verify the domain name.";
        }
    }
}
