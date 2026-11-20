using System;
using System.Windows;
using System.Windows.Threading;
using HueThemeKit;

namespace AclLegibility;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // App-owned extras (README "Deviations from HueTheme"). Loaded here rather than in App.xaml
        // so their BasedOn / StaticResource references find the kit's keys in the finished app resources.
        Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/AclLegibility;component/Theme/AclLegibility.Extras.xaml", UriKind.Relative),
        });
        base.OnStartup(e);
        HueContrast.Changed += (_, _) => ContrastLinks();
        HueContrast.Follow(this);
        DispatcherUnhandledException += OnUnhandled;
    }

    /// <summary>The link brushes are app-owned, so the kit's contrast swap doesn't reach them: under a Windows
    /// contrast theme they follow the system's hyperlink and grey text colours instead of the kit's indigo.</summary>
    private void ContrastLinks()
    {
        if (HueContrast.IsActive)
        {
            Resources["App.Brush.Link"] = SystemColors.HotTrackBrush;
            Resources["App.Brush.LinkMuted"] = SystemColors.GrayTextBrush;
        }
        else
        {
            Resources.Remove("App.Brush.Link");
            Resources.Remove("App.Brush.LinkMuted");
        }
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        try { HueMessage.Show(MainWindow, "Unexpected error", e.Exception.ToString()); }
        catch { /* the theme itself may be what failed */ }
    }
}
