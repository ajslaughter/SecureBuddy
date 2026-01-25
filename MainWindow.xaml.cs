using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;

namespace CyberShieldBuddy
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<SecurityCheckItem> _securityChecks = new ObservableCollection<SecurityCheckItem>();
        private ObservableCollection<FaqItem> _faqItems = new ObservableCollection<FaqItem>();
        private Storyboard? _scanningAnimation;

        public MainWindow()
        {
            InitializeComponent();
            AuditLogger.Log("Application started", "INFO");

            // Initialize data
            InitializeFaqItems();
            InitializeSecurityTips();

            // Bind collections
            SecurityChecksList.ItemsSource = _securityChecks;
            FaqList.ItemsSource = _faqItems;

            // Initial network refresh
            RefreshNetwork_Click(this, new RoutedEventArgs());

            // Create scanning animation
            CreateScanningAnimation();
        }

        private void CreateScanningAnimation()
        {
            _scanningAnimation = new Storyboard();
            var rotateAnimation = new DoubleAnimation
            {
                From = 0,
                To = 360,
                Duration = TimeSpan.FromSeconds(1.5),
                RepeatBehavior = RepeatBehavior.Forever
            };
            Storyboard.SetTarget(rotateAnimation, HealthStatusRing);
            Storyboard.SetTargetProperty(rotateAnimation, new PropertyPath("RenderTransform.Angle"));
            _scanningAnimation.Children.Add(rotateAnimation);
        }

        private void InitializeFaqItems()
        {
            _faqItems.Add(new FaqItem
            {
                Question = "Is this app safe to use?",
                Answer = "Yes! CyberShield Buddy only reads your system settings and makes changes when you explicitly click 'Harden Now'. " +
                         "The scanning process is completely safe and doesn't modify anything. All hardening changes follow Microsoft's " +
                         "recommended security best practices and can be reversed if needed."
            });

            _faqItems.Add(new FaqItem
            {
                Question = "Will this slow down my computer?",
                Answer = "No. The security settings this app configures have minimal to no impact on performance. " +
                         "Disabling unused features like Remote Desktop or SMBv1 can actually improve performance slightly " +
                         "because your computer won't be listening for connections on those services."
            });

            _faqItems.Add(new FaqItem
            {
                Question = "Do I need to be technical to use this?",
                Answer = "Not at all! CyberShield Buddy is designed for beginners. Just click 'Scan Now' to see your current " +
                         "security status, and 'Harden Now' to apply recommended settings. Click on any security check to learn " +
                         "what it means in plain English. If you're unsure about something, the Learn tab has helpful explanations."
            });

            _faqItems.Add(new FaqItem
            {
                Question = "What if something breaks after hardening?",
                Answer = "Most users won't notice any difference after hardening. However, if you use Remote Desktop to connect " +
                         "to this computer from elsewhere, you'll need to re-enable it. The app logs all changes it makes, " +
                         "and settings can be reversed through Windows Settings or by running this app again."
            });

            _faqItems.Add(new FaqItem
            {
                Question = "Why does it need administrator privileges?",
                Answer = "Changing security settings requires administrator access because they affect the entire system. " +
                         "This is a Windows security feature - it prevents malware from changing settings without your permission. " +
                         "You only need admin rights for the 'Harden Now' button; scanning works without it."
            });

            _faqItems.Add(new FaqItem
            {
                Question = "How often should I run a scan?",
                Answer = "We recommend running a scan after Windows updates, installing new software, or at least once a month. " +
                         "Windows updates sometimes reset security settings, and some software installers may enable features " +
                         "like Remote Desktop. Regular scanning helps ensure your settings stay secure."
            });
        }

        private void InitializeSecurityTips()
        {
            var tips = new List<dynamic>
            {
                new { Icon = "🔐", Title = "Use Strong, Unique Passwords",
                    Description = "Use a different password for each account. Consider using a password manager like Bitwarden (free) or 1Password to generate and store strong passwords." },

                new { Icon = "🔄", Title = "Keep Windows Updated",
                    Description = "Enable automatic updates in Windows Settings. Security patches fix vulnerabilities that hackers actively exploit. Most attacks target systems running outdated software." },

                new { Icon = "🛡️", Title = "Enable Windows Defender",
                    Description = "Windows Defender (built into Windows 10/11) provides solid protection for most users. Make sure it's enabled and running. You don't need to pay for additional antivirus software." },

                new { Icon = "📧", Title = "Be Suspicious of Emails",
                    Description = "Don't click links or download attachments from unexpected emails, even if they look official. Banks and legitimate companies never ask for passwords via email." },

                new { Icon = "💾", Title = "Back Up Your Data",
                    Description = "Use Windows Backup or a service like OneDrive to keep copies of important files. If ransomware encrypts your files, backups let you restore without paying." },

                new { Icon = "🔒", Title = "Lock Your Computer",
                    Description = "Press Win+L to lock your computer when stepping away. Enable a password or PIN for your Windows account. This prevents unauthorized access if someone walks by." },

                new { Icon = "📱", Title = "Enable Two-Factor Authentication",
                    Description = "Turn on 2FA for important accounts (email, banking, social media). Even if someone steals your password, they can't log in without your phone." },

                new { Icon = "🌐", Title = "Use HTTPS Websites",
                    Description = "Look for the padlock icon in your browser's address bar. HTTPS encrypts data between you and the website. Never enter passwords on sites without HTTPS." }
            };

            TipsList.ItemsSource = tips;
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ScanButton.IsEnabled = false;
                ScanButton.Content = "Scanning...";
                StatusText.Text = "Analyzing...";
                StatusEmoji.Text = "🔍";
                AuditLogger.Log("Security scan initiated", "INFO");

                // Start animation
                _scanningAnimation?.Begin();
                HealthStatusRing.Stroke = Brushes.DodgerBlue;

                // Simulate UX delay and run checks
                await Task.Delay(800);

                int score = SecurityEngine.CalculateHardeningScore();
                var checks = SecurityEngine.GetSecurityChecks();

                // Stop animation
                _scanningAnimation?.Stop();

                // Update UI
                ScoreText.Text = score.ToString();
                ScanButton.Content = "Scan Again";
                ScanButton.IsEnabled = true;

                // Update security checks list
                _securityChecks.Clear();
                foreach (var check in checks)
                {
                    _securityChecks.Add(check);
                }

                // Update status with emoji
                if (score == 100)
                {
                    HealthStatusRing.Stroke = Brushes.Green;
                    StatusText.Text = "Well Protected";
                    StatusEmoji.Text = "🛡️";
                    AuditLogger.Log($"Scan complete: Score {score} - Well Protected", "SUCCESS");
                }
                else if (score >= 80)
                {
                    HealthStatusRing.Stroke = Brushes.LightGreen;
                    StatusText.Text = "Good Security";
                    StatusEmoji.Text = "✅";
                    AuditLogger.Log($"Scan complete: Score {score} - Good Security", "SUCCESS");
                }
                else if (score >= 60)
                {
                    HealthStatusRing.Stroke = Brushes.Orange;
                    StatusText.Text = "Needs Attention";
                    StatusEmoji.Text = "⚠️";
                    AuditLogger.Log($"Scan complete: Score {score} - Needs Attention", "WARN");
                }
                else
                {
                    HealthStatusRing.Stroke = Brushes.Red;
                    StatusText.Text = "At Risk";
                    StatusEmoji.Text = "🚨";
                    AuditLogger.Log($"Scan complete: Score {score} - At Risk", "WARN");
                }

                // Animate score appearance
                AnimateScoreChange();
            }
            catch (Exception ex)
            {
                _scanningAnimation?.Stop();
                AuditLogger.Log($"Scan failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Scan failed: {ex.Message}", "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
                ScanButton.Content = "Scan Now";
                ScanButton.IsEnabled = true;
                HealthStatusRing.Stroke = Brushes.Gray;
            }
        }

        private void AnimateScoreChange()
        {
            var scaleAnimation = new DoubleAnimation
            {
                From = 0.8,
                To = 1.0,
                Duration = TimeSpan.FromMilliseconds(300),
                EasingFunction = new ElasticEase { EasingMode = EasingMode.EaseOut, Oscillations = 1 }
            };

            var transform = new ScaleTransform(1, 1);
            ScoreText.RenderTransform = transform;
            ScoreText.RenderTransformOrigin = new Point(0.5, 0.5);
            transform.BeginAnimation(ScaleTransform.ScaleXProperty, scaleAnimation);
            transform.BeginAnimation(ScaleTransform.ScaleYProperty, scaleAnimation);
        }

        private async void HardenButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "This will apply security hardening settings to your system. This requires administrator privileges.\n\n" +
                "Changes include:\n" +
                "• Disabling Remote Desktop\n" +
                "• Disabling SMBv1 protocol\n" +
                "• Enabling LSA Protection\n" +
                "• Disabling Guest account\n\n" +
                "Do you want to continue?",
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
                HardenButton.Content = "Harden Now";
                HardenButton.IsEnabled = true;
            }
        }

        private void CheckLink_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text;

            AuditLogger.Log($"Checking URL: {url}", "INFO");
            var results = SecurityEngine.AnalyzeUrlDetailed(url);
            LinkCheckResults.ItemsSource = results;

            // Log summary
            int warningCount = 0;
            foreach (var r in results)
            {
                if (r.Severity == "Warning" || r.Severity == "Caution")
                    warningCount++;
            }

            if (warningCount > 0)
            {
                AuditLogger.Log($"URL check found {warningCount} warnings: {url}", "WARN");
            }
            else
            {
                AuditLogger.Log($"URL check passed: {url}", "INFO");
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

        private void SecurityCheck_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is FrameworkElement element && element.Tag is SecurityCheckItem item)
            {
                item.IsExpanded = !item.IsExpanded;
            }
        }

        private void FaqItem_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is FrameworkElement element && element.Tag is FaqItem item)
            {
                item.IsExpanded = !item.IsExpanded;
            }
        }

        private void ShowTutorial_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var welcomeDialog = new WelcomeDialog();
                welcomeDialog.Owner = this;
                welcomeDialog.ShowDialog();
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Failed to show tutorial: {ex.Message}", "ERROR");
            }
        }
    }
}
