using System.Windows;
using HueThemeKit;
using Microsoft.Win32;

namespace AclLegibility;

/// <summary>
/// The consent for the six actions that change the machine. Declining keeps the app read-only: everything that reads works,
/// and the screen comes back when an action is clicked. Agreeing once is stored per user and holds until the text changes.
/// Same mechanics as FirewallManager's: HKCU value, a version that is bumped only when the text materially changes, and a
/// review mode (the logo) that records nothing.
/// </summary>
public partial class ConsentWindow : Window
{
    /// <summary>Bump when the text materially changes — forces a new agreement.</summary>
    private const int ConsentVersion = 1;
    private const string RegPath = @"Software\GeekAclTool";

    private readonly bool _reviewMode;

    public ConsentWindow()
    {
        InitializeComponent();
        HueTitleBar.Attach(this);
    }

    /// <summary>Review mode: the text with both ticks set and locked; Close only. Nothing is recorded.</summary>
    public ConsentWindow(bool reviewMode) : this()
    {
        if (!reviewMode) return;
        _reviewMode = true;
        Title = "ἈΝΑΓΝΩΣΙΣ — the terms you accepted";
        ChkWant.IsChecked = true; ChkWant.IsEnabled = false;
        ChkKnow.IsChecked = true; ChkKnow.IsEnabled = false;
        BtnDecline.Visibility = Visibility.Collapsed;
        BtnProceed.Content = "Close";
        BtnProceed.IsEnabled = true;
    }

    /// <summary>True when the stored agreement is for the current text or later.</summary>
    public static bool AlreadyAccepted()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(RegPath);
            return k?.GetValue("ConsentVersion") is int v && v >= ConsentVersion;
        }
        catch { return false; }
    }

    private void Chk_Changed(object sender, RoutedEventArgs e)
    {
        if (_reviewMode) return;
        BtnProceed.IsEnabled = ChkWant.IsChecked == true && ChkKnow.IsChecked == true;
    }

    private void BtnProceed_Click(object sender, RoutedEventArgs e)
    {
        if (_reviewMode) { Close(); return; }   // review mode records nothing
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(RegPath);
            k?.SetValue("ConsentVersion", ConsentVersion, RegistryValueKind.DWord);
        }
        catch { /* not stored: this session goes on, the screen comes back next launch */ }
        DialogResult = true;
        Close();
    }

    private void BtnDecline_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
