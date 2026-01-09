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
            // Initial scan/refresh
            RefreshNetwork_Click(null, null);
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            ScanButton.IsEnabled = false;
            ScanButton.Content = "Scanning...";
            StatusText.Text = "Analyzing...";

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
            }
            else if (score >= 60)
            {
                HealthStatusRing.Stroke = Brushes.Orange;
                StatusText.Text = "Room for Improvement";
            }
            else
            {
                HealthStatusRing.Stroke = Brushes.Red;
                StatusText.Text = "Action Required";
            }
            
            // List issues
            var issues = SecurityEngine.AuditFieldCompliance();
            IssuesList.ItemsSource = issues;
        }

        private void CheckLink_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text;
            string result = SecurityEngine.AnalyzeUrl(url);
            PhishingResult.Text = result;
            
            if (result.StartsWith("Warning") || result.StartsWith("Suspicious"))
                PhishingResult.Foreground = Brushes.Red;
            else if (result.StartsWith("Caution"))
                PhishingResult.Foreground = Brushes.Orange;
            else
                PhishingResult.Foreground = Brushes.Green;
        }

        private async void FixScreen_Click(object sender, RoutedEventArgs e)
        {
             await Task.Run(() => SecurityEngine.FixDisplayResolution());
             MessageBox.Show("Display drivers reset! Please restart your PC if the issue persists.", "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private async void RefreshNetwork_Click(object sender, RoutedEventArgs e)
        {
            try
            {
               var connections = await Task.Run(() => SecurityEngine.GetNetworkConnections());
               NetworkList.ItemsSource = connections;
            }
            catch
            {
                // In case of error
            }
        }
    }
}
