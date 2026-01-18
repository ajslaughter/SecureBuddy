using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Data;

namespace CyberShieldBuddy
{
    public class AuditLogEntry
    {
        public string Timestamp { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string Type { get; set; } = "INFO"; // INFO, WARN, ERROR, SUCCESS
    }

    public static class AuditLogger
    {
        private static readonly object _lock = new object();
        public static ObservableCollection<AuditLogEntry> Logs { get; } = new ObservableCollection<AuditLogEntry>();

        static AuditLogger()
        {
            // Enable collection synchronization for cross-thread access
            BindingOperations.EnableCollectionSynchronization(Logs, _lock);
        }

        public static void Log(string message, string type = "INFO")
        {
            lock (_lock)
            {
                var entry = new AuditLogEntry
                {
                    Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                    Message = message,
                    Type = type
                };
                Logs.Add(entry);

                // Persist to file for post-crash analysis
                try
                {
                    string logPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "CyberShieldBuddy",
                        "audit.log"
                    );
                    Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
                    File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{type}] {message}{Environment.NewLine}");
                }
                catch
                {
                    // Swallow file IO errors to prevent recursive crash
                }
            }
        }
    }
}
