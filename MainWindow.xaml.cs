using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

namespace CyberShieldBuddy
{
    public partial class MainWindow : Window
    {
        // ═══════════════════════════════════════════════════════════════
        // CYBER-NOIR THEME COLORS
        // ═══════════════════════════════════════════════════════════════
        private static readonly Color CyanPrimary = (Color)ColorConverter.ConvertFromString("#06b6d4");
        private static readonly Color StatusSafe = (Color)ColorConverter.ConvertFromString("#10b981");
        private static readonly Color StatusWarning = (Color)ColorConverter.ConvertFromString("#f59e0b");
        private static readonly Color StatusDanger = (Color)ColorConverter.ConvertFromString("#ef4444");
        private static readonly Color TextMuted = (Color)ColorConverter.ConvertFromString("#6b7280");

        // ═══════════════════════════════════════════════════════════════
        // ANIMATION STATE
        // ═══════════════════════════════════════════════════════════════
        private DispatcherTimer _radarSweepTimer;
        private DispatcherTimer _scoreAnimationTimer;
        private int _targetScore;
        private int _currentDisplayScore;
        private DateTime _lastScanTime;
        private bool _isScanning;

        // Stats tracking
        private int _protectedCount;
        private int _warningsCount;
        private int _connectionsCount;

        public MainWindow()
        {
            InitializeComponent();
            AuditLogger.Log("Application started - Premium Cyber-Noir Edition", "INFO");

            // Initialize radar sweep animation
            InitializeRadarAnimation();

            // Initial network refresh
            RefreshNetwork_Click(this, new RoutedEventArgs());
        }

        // ═══════════════════════════════════════════════════════════════
        // RADAR ANIMATION
        // ═══════════════════════════════════════════════════════════════

        private void InitializeRadarAnimation()
        {
            _radarSweepTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(20)
            };
            _radarSweepTimer.Tick += RadarSweep_Tick;
        }

        private void RadarSweep_Tick(object sender, EventArgs e)
        {
            var currentAngle = RadarSweepRotation.Angle;
            RadarSweepRotation.Angle = (currentAngle + 3) % 360;
        }

        private void StartRadarAnimation()
        {
            RadarSweepLine.Opacity = 0.6;
            _radarSweepTimer.Start();
        }

        private void StopRadarAnimation()
        {
            _radarSweepTimer.Stop();
            RadarSweepLine.Opacity = 0.2;
        }

        // ═══════════════════════════════════════════════════════════════
        // ANIMATED SCORE COUNTING
        // ═══════════════════════════════════════════════════════════════

        private void AnimateScoreTo(int targetScore)
        {
            _targetScore = targetScore;
            _currentDisplayScore = 0;

            _scoreAnimationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(20)
            };
            _scoreAnimationTimer.Tick += ScoreAnimation_Tick;
            _scoreAnimationTimer.Start();
        }

        private void ScoreAnimation_Tick(object sender, EventArgs e)
        {
            // Ease-out animation
            int remaining = _targetScore - _currentDisplayScore;
            int increment = Math.Max(1, remaining / 8);

            _currentDisplayScore += increment;

            if (_currentDisplayScore >= _targetScore)
            {
                _currentDisplayScore = _targetScore;
                _scoreAnimationTimer.Stop();
            }

            ScoreText.Text = _currentDisplayScore.ToString();
            UpdateProgressRing(_currentDisplayScore, GetScoreColor(_targetScore));
        }

        private Color GetScoreColor(int score)
        {
            if (score >= 100) return StatusSafe;
            if (score >= 60) return StatusWarning;
            return StatusDanger;
        }

        // ═══════════════════════════════════════════════════════════════
        // PROGRESS RING RENDERING
        // ═══════════════════════════════════════════════════════════════

        private void UpdateProgressRing(int score, Color ringColor)
        {
            // Calculate the arc endpoint based on score (0-100)
            double percentage = score / 100.0;
            double angle = percentage * 360;

            // Center of the canvas and radius (adjusted for new size)
            double centerX = 110;
            double centerY = 110;
            double radius = 103;

            // Start point is at the top (12 o'clock position)
            double startAngle = -90;
            double endAngle = startAngle + angle;

            // Convert to radians
            double endAngleRad = endAngle * Math.PI / 180;

            // Calculate the end point
            double endX = centerX + radius * Math.Cos(endAngleRad);
            double endY = centerY + radius * Math.Sin(endAngleRad);

            // Update the arc segment
            ProgressFigure.StartPoint = new Point(centerX, centerY - radius);
            ProgressArcSegment.Point = new Point(endX, endY);
            ProgressArcSegment.Size = new Size(radius, radius);
            ProgressArcSegment.IsLargeArc = angle > 180;
            ProgressArcSegment.SweepDirection = SweepDirection.Clockwise;

            // Animate color transition
            AnimateProgressColor(ringColor);
        }

        private void AnimateProgressColor(Color targetColor)
        {
            var colorAnimation = new ColorAnimation
            {
                To = targetColor,
                Duration = TimeSpan.FromMilliseconds(500),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            ProgressArcBrush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnimation);
            ProgressGlow.Color = targetColor;
        }

        // ═══════════════════════════════════════════════════════════════
        // STATS DASHBOARD UPDATES
        // ═══════════════════════════════════════════════════════════════

        private void UpdateStatsDashboard(List<SecurityCheckResult> checks)
        {
            _protectedCount = checks.Count(c => c.Status == SecurityStatus.Safe);
            _warningsCount = checks.Count(c => c.Status == SecurityStatus.Warning || c.Status == SecurityStatus.Unsafe);

            // Animate stats counting
            AnimateStatCount(ProtectedCount, _protectedCount);
            AnimateStatCount(WarningsCount, _warningsCount);

            // Update last scan time
            _lastScanTime = DateTime.Now;
            LastScanTime.Text = _lastScanTime.ToString("HH:mm");
            LastScanDate.Text = _lastScanTime.ToString("MMM dd, yyyy");

            // Update system status
            UpdateSystemStatus(_protectedCount, _warningsCount);
        }

        private async void AnimateStatCount(System.Windows.Controls.TextBlock textBlock, int targetValue)
        {
            int current = 0;
            int increment = Math.Max(1, targetValue / 10);

            while (current < targetValue)
            {
                current = Math.Min(current + increment, targetValue);
                textBlock.Text = current.ToString();
                await Task.Delay(30);
            }
        }

        private void UpdateSystemStatus(int safe, int warnings)
        {
            if (warnings == 0 && safe > 0)
            {
                SystemStatusDot.Fill = new SolidColorBrush(StatusSafe);
                SystemStatusText.Text = "All Systems Secure";
            }
            else if (warnings > 0 && warnings <= 2)
            {
                SystemStatusDot.Fill = new SolidColorBrush(StatusWarning);
                SystemStatusText.Text = "Minor Issues Detected";
            }
            else if (warnings > 2)
            {
                SystemStatusDot.Fill = new SolidColorBrush(StatusDanger);
                SystemStatusText.Text = "Action Required";
            }
            else
            {
                SystemStatusDot.Fill = new SolidColorBrush(CyanPrimary);
                SystemStatusText.Text = "System Online";
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // SCAN BUTTON HANDLER
        // ═══════════════════════════════════════════════════════════════

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;

            try
            {
                _isScanning = true;
                ScanButton.IsEnabled = false;
                ScanButtonText.Text = "Scanning...";
                StatusText.Text = "ANALYZING";
                AuditLogger.Log("Security scan initiated", "INFO");

                // Start radar animation
                StartRadarAnimation();

                // Simulate scanning with visual feedback
                await Task.Delay(1200);

                // Calculate score
                int score = SecurityEngine.CalculateHardeningScore();

                // Stop radar animation
                StopRadarAnimation();

                // Animate score counting
                AnimateScoreTo(score);

                // Update status text based on score
                if (score == 100)
                {
                    StatusText.Text = "FULLY PROTECTED";
                    AuditLogger.Log($"Scan complete: Score {score} - Fully Protected", "SUCCESS");
                }
                else if (score >= 60)
                {
                    StatusText.Text = "NEEDS ATTENTION";
                    AuditLogger.Log($"Scan complete: Score {score} - Needs Attention", "WARN");
                }
                else
                {
                    StatusText.Text = "ACTION REQUIRED";
                    AuditLogger.Log($"Scan complete: Score {score} - Action Required", "WARN");
                }

                // Populate security status cards
                var securityChecks = SecurityEngine.GetAllSecurityChecks();
                SecurityChecksList.ItemsSource = securityChecks;
                SecurityCardsSection.Visibility = Visibility.Visible;

                // Update stats dashboard
                UpdateStatsDashboard(securityChecks);

                // Reset button
                ScanButtonText.Text = "Scan Again";
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Scan failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Scan failed: {ex.Message}", "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusText.Text = "SCAN FAILED";
                ScanButtonText.Text = "Retry Scan";
                StopRadarAnimation();
            }
            finally
            {
                ScanButton.IsEnabled = true;
                _isScanning = false;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // HARDEN BUTTON HANDLER
        // ═══════════════════════════════════════════════════════════════

        private async void HardenButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "This will apply security hardening settings to your system.\n\nThis requires administrator privileges.\n\nDo you want to continue?",
                "CyberShield Buddy - Confirm Hardening",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes)
                return;

            try
            {
                HardenButton.IsEnabled = false;
                HardenButtonText.Text = "Hardening...";
                AuditLogger.Log("Security hardening initiated", "INFO");

                // Start radar animation during hardening
                StartRadarAnimation();

                await Task.Run(() => SecurityEngine.ApplyHardeningBaseline());

                StopRadarAnimation();

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
                StopRadarAnimation();
            }
            finally
            {
                HardenButtonText.Text = "Harden";
                HardenButton.IsEnabled = true;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // LINK CHECKER
        // ═══════════════════════════════════════════════════════════════

        private void CheckLink_Click(object sender, RoutedEventArgs e)
        {
            string url = UrlInput.Text;
            if (string.IsNullOrWhiteSpace(url))
            {
                ShowPhishingResult("Please enter a URL to analyze.", TextMuted, "\uE946");
                return;
            }

            AuditLogger.Log($"Analyzing URL: {url}", "INFO");
            var analysis = SecurityEngine.AnalyzeUrlAdvanced(url);

            PhishingResultBorder.Visibility = Visibility.Visible;
            PhishingResult.Text = analysis.Message;

            Color resultColor;
            string resultIcon;

            switch (analysis.ThreatLevel)
            {
                case ThreatLevel.Safe:
                    resultColor = StatusSafe;
                    resultIcon = "\uE73E";
                    AuditLogger.Log($"URL analysis: Safe - {url}", "INFO");
                    break;
                case ThreatLevel.Caution:
                    resultColor = StatusWarning;
                    resultIcon = "\uE7BA";
                    AuditLogger.Log($"URL analysis: Caution - {url}", "WARN");
                    break;
                case ThreatLevel.Danger:
                    resultColor = StatusDanger;
                    resultIcon = "\uE711";
                    AuditLogger.Log($"URL analysis: Danger - {url}", "WARN");
                    break;
                default:
                    resultColor = TextMuted;
                    resultIcon = "\uE946";
                    break;
            }

            ShowPhishingResult(analysis.Message, resultColor, resultIcon);
        }

        private void ShowPhishingResult(string message, Color color, string icon)
        {
            PhishingResultBorder.Visibility = Visibility.Visible;
            PhishingResult.Text = message;
            PhishingResult.Foreground = new SolidColorBrush(color);
            PhishingResultIcon.Text = icon;
            PhishingResultIcon.Foreground = new SolidColorBrush(color);
        }

        // ═══════════════════════════════════════════════════════════════
        // SECURITY CARD CLICK
        // ═══════════════════════════════════════════════════════════════

        private void SecurityCard_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (sender is FrameworkElement element && element.DataContext is SecurityCheckResult check)
            {
                AuditLogger.Log($"Security card clicked: {check.Title} - Status: {check.Status}", "INFO");
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // DISPLAY FIX
        // ═══════════════════════════════════════════════════════════════

        private async void FixScreen_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                AuditLogger.Log("Display fix initiated", "INFO");
                await Task.Run(() => SecurityEngine.FixDisplayResolution());
                AuditLogger.Log("Display fix completed", "SUCCESS");
                MessageBox.Show("Display drivers reset!\n\nPlease restart your PC if the issue persists.",
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Display fix failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Failed to reset display: {ex.Message}",
                    "CyberShield Buddy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // NETWORK GUARDIAN
        // ═══════════════════════════════════════════════════════════════

        private async void RefreshNetwork_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var connections = await Task.Run(() => SecurityEngine.GetNetworkConnections());
                NetworkList.ItemsSource = connections;
                _connectionsCount = connections.Count;

                // Animate connections count
                AnimateStatCount(ConnectionsCount, _connectionsCount);

                AuditLogger.Log($"Network scan complete: {connections.Count} connections found", "INFO");
            }
            catch (Exception ex)
            {
                AuditLogger.Log($"Network scan failed: {ex.Message}", "ERROR");
                NetworkList.ItemsSource = null;
                ConnectionsCount.Text = "0";
            }
        }
    }
}
