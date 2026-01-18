using System;
using System.Windows;
using System.Windows.Media;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CyberShieldBuddy
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            AuditLogger.Log("Application started", "INFO");
            // Initial scan/refresh
            RefreshNetwork_Click(null, null);
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ScanButton.IsEnabled = false;
                ScanButton.Content = "Scanning...";
                StatusText.Text = "Analyzing...";
                AuditLogger.Log("Security scan initiated", "INFO");

                // Simulate UX delay
                await Task.Delay(800);

                int score = SecurityEngine.CalculateHardeningScore();
                
                // Update UI
                ScoreText.Text = score.ToString();
                ScanButton.Content = "Scan Again";
                ScanButton.IsEnabled = true;

                if (score == 100)
                {
                    HealthStatusRing.Stroke = Brushes.Green;
                    StatusText.Text = "Fully Protected";
                    AuditLogger.Log($"Scan complete: Score {score} - Fully Protected", "SUCCESS");
                }
                else if (score >= 60)
                {
                    HealthStatusRing.Stroke = Brushes.Orange;
                    StatusText.Text = "Room for Improvement";
                    AuditLogger.Log($"Scan complete: Score {score} - Room for Improvement", "WARN");
                }
                else
                {
                    HealthStatusRing.Stroke = Brushes.Red;
                    StatusText.Text = "Action Required";
                    AuditLogger.Log($"Scan complete: Score {score} - Action Required", "WARN");
                }
                
                // List issues
                var issues = SecurityEngine.AuditFieldCompliance();
                IssuesList.ItemsSource = issues;
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Scan failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Scan failed: {ex.Message}", "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
                ScanButton.Content = "Scan Now";
                ScanButton.IsEnabled = true;
            }
        }

        private async void HardenButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "This will apply security hardening settings to your system. This requires administrator privileges.\n\nDo you want to continue?",
                "CyberShield Buddy - Confirm Hardening",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes)
                return;

            try
            {
                HardenButton.IsEnabled = false;
                HardenButton.Content = "Hardening...";
                AuditLogger.Log("Security hardening initiated", "INFO");

                await Task.Run(() => SecurityEngine.ApplyHardeningBaseline());

                AuditLogger.Log("Security hardening completed successfully", "SUCCESS");
                MessageBox.Show("Security hardening applied successfully!\n\nSome changes may require a restart to take effect.", 
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Information);

                // Re-scan to update the score
                ScanButton_Click(null, null);
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Hardening failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Hardening failed: {ex.Message}\n\nMake sure you're running as Administrator.", 
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                HardenButton.Content = "Harden Now";
                HardenButton.IsEnabled = true;
            }
        }

        private void CheckLink_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text;
            if (string.IsNullOrWhiteSpace(url))
            {
                PhishingResult.Text = "Please enter a URL to check.";
                PhishingResult.Foreground = Brushes.Gray;
                return;
            }

            AuditLogger.Log($"Checking URL: {url}", "INFO");
            string analysisResult = SecurityEngine.AnalyzeUrl(url);
            PhishingResult.Text = analysisResult;
            
            if (analysisResult.StartsWith("Warning") || analysisResult.StartsWith("Suspicious"))
            {
                PhishingResult.Foreground = Brushes.Red;
                AuditLogger.Log($"URL flagged as suspicious: {url}", "WARN");
            }
            else if (analysisResult.StartsWith("Caution"))
            {
                PhishingResult.Foreground = Brushes.Orange;
                AuditLogger.Log($"URL flagged with caution: {url}", "WARN");
            }
            else
            {
                PhishingResult.Foreground = Brushes.Green;
                AuditLogger.Log($"URL appears safe: {url}", "SUCCESS");
            }
        }

        private async void FixScreen_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AuditLogger.Log("Display fix initiated", "INFO");
                await Task.Run(() => SecurityEngine.FixDisplayResolution());
                AuditLogger.Log("Display fix completed", "SUCCESS");
                MessageBox.Show("Display drivers reset! Please restart your PC if the issue persists.", 
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Display fix failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Failed to reset display: {ex.Message}", 
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void RefreshNetwork_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var connections = await Task.Run(() => SecurityEngine.GetNetworkConnections());
                NetworkList.ItemsSource = connections;
                AuditLogger.Log($"Network scan complete: {connections.Count} connections found", "INFO");
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Network scan failed: {ex.Message}", "ERROR");
                NetworkList.ItemsSource = null;
            }
        }
    }
}
