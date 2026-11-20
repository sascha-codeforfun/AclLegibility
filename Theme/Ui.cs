using System;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using AclLegibility.Model;

namespace AclLegibility.Theme;

/// <summary>App-side helpers for the HueTheme kit: which style or icon an origin or a node gets.
/// Colours are never read here — only style and resource keys, so contrast themes still apply.</summary>
public static class Ui
{
    /// <summary>The tag style for an origin. See README "Deviations from HueTheme".</summary>
    public static string TagStyleKey(Origin o) => o switch
    {
        Origin.Modified => "Hue.Tag.Unsafe",
        Origin.Custom => "Hue.Tag.Caution",
        Origin.Unknown => "Hue.Tag",
        _ => "App.Tag.Quiet",          // Stock, Stock per account, Differs, Trace, None
    };

    public static Style TagStyle(Origin o) => (Style)Application.Current.FindResource(TagStyleKey(o));

    public static string IconKey(ScanNode n)
    {
        if (n.IsRoot && (n.Flags & NodeFlags.IsVolumeRoot) != 0) return "Icon.Drive";
        if (n.Extra?.Reparse != null) return "Icon.Link";
        return n.IsDirectory ? "Icon.Folder" : "Icon.File";
    }

    /// <summary>How a link is drawn: "Full" (indigo) for a link that is not stock, "Muted" for a stock one, "" otherwise.</summary>
    public static string LinkLook(ScanNode n)
    {
        if (!n.IsLink) return "";
        var f = n.Findings?.FirstOrDefault(x => x.Category == FindingCategory.Link);
        return f != null && f.Origin is Origin.Stock or Origin.Trace or Origin.Differs or Origin.PerAccount ? "Muted" : "Full";
    }

    /// <summary>"1 object", "2 objects", with thousands separators.</summary>
    public static string Objects(long n) => n == 1 ? "1 object" : $"{n:N0} objects";

    /// <summary>A capability SID without a known name: "Capability (unnamed) S-1-15-3-…-230526575", so several can be told apart.</summary>
    public static string? UnnamedCapability(string sid)
    {
        if (!sid.StartsWith("S-1-15-3-", System.StringComparison.OrdinalIgnoreCase)) return null;
        var last = sid[(sid.LastIndexOf('-') + 1)..];
        return $"Capability (unnamed) S-1-15-3-…-{last}";
    }

    /// <summary>"1 folder", "0 folders", "2 folders".</summary>
    public static string Count(long n, string singular, string? plural = null) =>
        n == 1 ? "1 " + singular : $"{n:N0} " + (plural ?? singular + "s");

    public static string Size(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double v = bytes; string[] u = { "KB", "MB", "GB", "TB" }; int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < u.Length - 1);
        return $"{v:0.#} {u[i]}";
    }

    /// <summary>A fixed-width elapsed time for the header pill: 00:18, 1:02:03.</summary>
    public static string Elapsed(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}:{t.Minutes:00}:{t.Seconds:00}" : $"{t.Minutes:00}:{t.Seconds:00}";
}

/// <summary>Origin → the tag style the list rows use (also used inside filter pills).</summary>
public sealed class OriginTagStyleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Origin o ? Ui.TagStyle(o) : Ui.TagStyle(Origin.None);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Resource key → icon geometry (geometries may be static; only brushes must be dynamic).</summary>
public sealed class IconGeometryConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is string key ? Application.Current.TryFindResource(key) : null;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
