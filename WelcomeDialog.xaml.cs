using System.Windows;
using System.Windows.Media;

namespace CyberShieldBuddy
{
    public partial class WelcomeDialog : Window
    {
        private int _currentStep = 1;

        public WelcomeDialog()
        {
            InitializeComponent();
        }

        private void UpdateStepDisplay()
        {
            // Hide all panels
            Step1Panel.Visibility = Visibility.Collapsed;
            Step2Panel.Visibility = Visibility.Collapsed;
            Step3Panel.Visibility = Visibility.Collapsed;

            // Reset dot colors
            var inactiveColor = (Brush)FindResource("SystemControlBackgroundBaseLowBrush");
            var activeColor = (Brush)FindResource("SystemControlBackgroundAccentBrush");

            Step1Dot.Fill = inactiveColor;
            Step2Dot.Fill = inactiveColor;
            Step3Dot.Fill = inactiveColor;

            // Show current panel and update dot
            switch (_currentStep)
            {
                case 1:
                    Step1Panel.Visibility = Visibility.Visible;
                    Step1Dot.Fill = activeColor;
                    BackButton.Visibility = Visibility.Collapsed;
                    NextButton.Content = "Next";
                    break;
                case 2:
                    Step2Panel.Visibility = Visibility.Visible;
                    Step2Dot.Fill = activeColor;
                    BackButton.Visibility = Visibility.Visible;
                    NextButton.Content = "Next";
                    break;
                case 3:
                    Step3Panel.Visibility = Visibility.Visible;
                    Step3Dot.Fill = activeColor;
                    BackButton.Visibility = Visibility.Visible;
                    NextButton.Content = "Get Started";
                    break;
            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentStep > 1)
            {
                _currentStep--;
                UpdateStepDisplay();
            }
        }

        private void NextButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentStep < 3)
            {
                _currentStep++;
                UpdateStepDisplay();
            }
            else
            {
                // Final step - close dialog
                DialogResult = true;
                Close();
            }
        }

        private void SkipButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }
    }
}
