using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CyberShieldBuddy
{
    public partial class MainWindow : Window
    {
        // Theme colors from App.xaml
        private static readonly Color EmeraldSafe = (Color)ColorConverter.ConvertFromString("#10b981");
        private static readonly Color AmberWarning = (Color)ColorConverter.ConvertFromString("#f59e0b");
        private static readonly Color RoseDanger = (Color)ColorConverter.ConvertFromString("#f43f5e");
        private static readonly Color TextMuted = (Color)ColorConverter.ConvertFromString("#64748b");

        public MainWindow()
        {
            InitializeComponent();
            AuditLogger.Log("Application started", "INFO");
            // Initial scan/refresh
            RefreshNetwork_Click(this, new RoutedEventArgs());
        }

        private void UpdateProgressRing(int score, Color ringColor)
        {
            // Calculate the arc endpoint based on score (0-100)
            double percentage = score / 100.0;
            double angle = percentage * 360;

            // Center of the canvas and radius
            double centerX = 90;
            double centerY = 90;
            double radius = 84;

            // Start point is at the top (12 o'clock position)
            double startAngle = -90; // degrees from 3 o'clock position
            double endAngle = startAngle + angle;

            // Convert to radians
            double endAngleRad = endAngle * Math.PI / 180;

            // Calculate the end point
            double endX = centerX + radius * Math.Cos(endAngleRad);
            double endY = centerY + radius * Math.Sin(endAngleRad);

            // Update the arc segment
            ProgressFigure.StartPoint = new Point(centerX, centerY - radius); // Top center
            ProgressArcSegment.Point = new Point(endX, endY);
            ProgressArcSegment.Size = new Size(radius, radius);
            ProgressArcSegment.IsLargeArc = angle > 180;
            ProgressArcSegment.SweepDirection = SweepDirection.Clockwise;

            // Update the color
            ProgressArcBrush.Color = ringColor;
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ScanButton.IsEnabled = false;
                StatusText.Text = "Analyzing...";
                AuditLogger.Log("Security scan initiated", "INFO");

                // Update button content to show scanning state
                var scanContent = ScanButton.Content as System.Windows.Controls.StackPanel;
                if (scanContent != null && scanContent.Children.Count > 1)
                {
                    var textBlock = scanContent.Children[1] as System.Windows.Controls.TextBlock;
                    if (textBlock != null) textBlock.Text = "Scanning...";
                }

                // Simulate UX delay
                await Task.Delay(800);

                int score = SecurityEngine.CalculateHardeningScore();

                // Update UI
                ScoreText.Text = score.ToString();

                // Restore button content
                if (scanContent != null && scanContent.Children.Count > 1)
                {
                    var textBlock = scanContent.Children[1] as System.Windows.Controls.TextBlock;
                    if (textBlock != null) textBlock.Text = "Scan Again";
                }
                ScanButton.IsEnabled = true;

                if (score == 100)
                {
                    UpdateProgressRing(score, EmeraldSafe);
                    StatusText.Text = "Fully Protected";
                    AuditLogger.Log($"Scan complete: Score {score} - Fully Protected", "SUCCESS");
                }
                else if (score >= 60)
                {
                    UpdateProgressRing(score, AmberWarning);
                    StatusText.Text = "Room for Improvement";
                    AuditLogger.Log($"Scan complete: Score {score} - Room for Improvement", "WARN");
                }
                else
                {
                    UpdateProgressRing(score, RoseDanger);
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

                var scanContent = ScanButton.Content as System.Windows.Controls.StackPanel;
                if (scanContent != null && scanContent.Children.Count > 1)
                {
                    var textBlock = scanContent.Children[1] as System.Windows.Controls.TextBlock;
                    if (textBlock != null) textBlock.Text = "Scan Now";
                }
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

                // Update button content to show hardening state
                var hardenContent = HardenButton.Content as System.Windows.Controls.StackPanel;
                if (hardenContent != null && hardenContent.Children.Count > 1)
                {
                    var textBlock = hardenContent.Children[1] as System.Windows.Controls.TextBlock;
                    if (textBlock != null) textBlock.Text = "Hardening...";
                }

                AuditLogger.Log("Security hardening initiated", "INFO");

                await Task.Run(() => SecurityEngine.ApplyHardeningBaseline());

                AuditLogger.Log("Security hardening completed successfully", "SUCCESS");
                MessageBox.Show("Security hardening applied successfully!\n\nSome changes may require a restart to take effect.",
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Information);

                // Re-scan to update the score
                ScanButton_Click(this, new RoutedEventArgs());
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Hardening failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Hardening failed: {ex.Message}\n\nMake sure you're running as Administrator.",
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                // Restore button content
                var hardenContent = HardenButton.Content as System.Windows.Controls.StackPanel;
                if (hardenContent != null && hardenContent.Children.Count > 1)
                {
                    var textBlock = hardenContent.Children[1] as System.Windows.Controls.TextBlock;
                    if (textBlock != null) textBlock.Text = "Harden Now";
                }
                HardenButton.IsEnabled = true;
            }
        }

        private void CheckLink_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text;
            if (string.IsNullOrWhiteSpace(url))
            {
                PhishingResultBorder.Visibility = Visibility.Visible;
                PhishingResult.Text = "Please enter a URL to check.";
                PhishingResult.Foreground = new SolidColorBrush(TextMuted);
                PhishingResultIcon.Text = "\uE946"; // Info icon
                PhishingResultIcon.Foreground = new SolidColorBrush(TextMuted);
                return;
            }

            AuditLogger.Log($"Checking URL: {url}", "INFO");
            string analysisResult = SecurityEngine.AnalyzeUrl(url);

            PhishingResultBorder.Visibility = Visibility.Visible;
            PhishingResult.Text = analysisResult;

            if (analysisResult.StartsWith("Warning") || analysisResult.StartsWith("Suspicious"))
            {
                PhishingResult.Foreground = new SolidColorBrush(RoseDanger);
                PhishingResultIcon.Text = "\uE7BA"; // Error icon
                PhishingResultIcon.Foreground = new SolidColorBrush(RoseDanger);
                AuditLogger.Log($"URL flagged as suspicious: {url}", "WARN");
            }
            else if (analysisResult.Contains("Note:") || analysisResult.Contains("ℹ️"))
            {
                PhishingResult.Foreground = new SolidColorBrush(AmberWarning);
                PhishingResultIcon.Text = "\uE7BA"; // Warning icon
                PhishingResultIcon.Foreground = new SolidColorBrush(AmberWarning);
                AuditLogger.Log($"URL flagged with note: {url}", "INFO");
            }
            else
            {
                PhishingResult.Foreground = new SolidColorBrush(EmeraldSafe);
                PhishingResultIcon.Text = "\uE73E"; // Checkmark icon
                PhishingResultIcon.Foreground = new SolidColorBrush(EmeraldSafe);
                AuditLogger.Log($"No red flags found in URL: {url}", "INFO");
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
