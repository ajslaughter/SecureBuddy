using System;
using System.IO;
using System.Windows;

namespace CyberShieldBuddy
{
    public partial class App : Application
    {
        public App()
        {
            // Catch all unhandled exceptions
            this.DispatcherUnhandledException += App_DispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
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
