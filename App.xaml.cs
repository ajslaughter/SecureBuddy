using System;
using System.IO;
using System.Windows;

namespace CyberShieldBuddy
{
    public partial class App : Application
    {
        private static readonly string AppDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CyberShieldBuddy");

        private static readonly string FirstRunFlagFile = Path.Combine(AppDataFolder, ".first_run_complete");

        public App()
        {
            // Catch all unhandled exceptions
            this.DispatcherUnhandledException += App_DispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Check if this is the first run
            if (IsFirstRun())
            {
                ShowWelcomeDialog();
                MarkFirstRunComplete();
            }
        }

        public static bool IsFirstRun()
        {
            return !File.Exists(FirstRunFlagFile);
        }

        private void ShowWelcomeDialog()
        {
            try
            {
                var welcomeDialog = new WelcomeDialog();
                welcomeDialog.ShowDialog();
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Failed to show welcome dialog: {ex.Message}", "ERROR");
            }
        }

        private void MarkFirstRunComplete()
        {
            try
            {
                Directory.CreateDirectory(AppDataFolder);
                File.WriteAllText(FirstRunFlagFile, DateTime.Now.ToString("o"));
                AuditLogger.Log("First run tutorial completed", "INFO");
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Failed to mark first run complete: {ex.Message}", "ERROR");
            }
        }

        public static void ResetFirstRun()
        {
            try
            {
                if (File.Exists(FirstRunFlagFile))
                {
                    File.Delete(FirstRunFlagFile);
                }
            }
            catch { }
        }

        private void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            LogAndShowError(e.Exception, "UI Thread Exception");
            e.Handled = true; // Prevent app from crashing without feedback
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                LogAndShowError(ex, "Fatal Exception");
            }
        }

        private void LogAndShowError(Exception ex, string source)
        {
            string errorMessage = $"{source}: {ex.Message}\n\nStack Trace:\n{ex.StackTrace}";
            
            // Log to file
            try
            {
                string logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "CyberShieldBuddy",
                    "crash.log"
                );
                Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
                File.AppendAllText(logPath, $"\n\n=== {DateTime.Now} ===\n{errorMessage}");
            }
            catch { }

            // Show to user
            MessageBox.Show(
                $"CyberShield Buddy encountered an error:\n\n{ex.Message}\n\nPlease report this issue.",
                "CyberShield Buddy - Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }
}
