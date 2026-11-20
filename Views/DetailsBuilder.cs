using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using AclLegibility.Export;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Native;
using AclLegibility.Security;
using AclLegibility.Theme;
using AclLegibility.ViewModels;

namespace AclLegibility.Views;

public sealed class DetailsContext
{
    public required ScanResult R { get; init; }
    public required CompiledKb Kb { get; init; }
    public required Classifier Cls { get; init; }
    public required IReadOnlyList<PrincipalRowVm> Principals { get; init; }
    public required Action<ScanNode> CopyNodeForAi { get; init; }
    public required Action<ScanNode> CopySubtreeForAi { get; init; }
    public required Action<string> CopyPrincipalForAi { get; init; }
    public required Action<ScanNode> Reveal { get; init; }
    public required Action<string> ShowPrincipal { get; init; }
    public required Action<string, string> CopyText { get; init; }   // text, status message
    public required Func<ScanNode, string?> ResetWhyNot { get; init; }
    public required Action<ScanNode> StartReset { get; init; }
    public required Func<string?> CleanupWhyNot { get; init; }
    public required Action<IReadOnlyCollection<string>> StartCleanup { get; init; }
    public required Func<string?> GrantWhyNot { get; init; }
    /// <summary>Account SID, the single folder (or null for all of the account's grants), and whether it was started from Accounts & groups.</summary>
    public required Action<string, ScanNode?, bool> StartGrantUndo { get; init; }
    /// <summary>Runs Windows' component-store clean-up; the flag adds /ResetBase.</summary>
    /// <summary>Points at the action row's Component store clean-up button (it pulses and takes focus); runs nothing.</summary>
    public required Action PointToComponentCleanup { get; init; }
    public required Action<ScanNode> StartDownloadMarks { get; init; }
}

/// <summary>Builds the detail panels in code: they vary too much per object for a fixed XAML layout.
/// Every colour goes through the theme (styles or SetResourceReference), never a brush object.</summary>
public static class DetailsBuilder
{
    private static string? _lastEffectiveSid;

    // ---- primitives ---------------------------------------------------------------------------

    private static Style S(string key) => (Style)Application.Current.FindResource(key);

    /// <summary>Text colour from a theme token (TextBlock and Control share TextElement.Foreground).</summary>
    private static T Fg<T>(T e, string brushKey) where T : FrameworkElement
    {
        e.SetResourceReference(TextElement.ForegroundProperty, brushKey);
        return e;
    }

    private static TextBlock Section(string text) => new()
    {
        Text = text.ToUpperInvariant(), Style = S("Text.Section"), Margin = new Thickness(0, 22, 0, 8),
    };

    /// <summary>Body text in full text colour.</summary>
    private static TextBlock T(string text) =>
        Fg(new TextBlock { Text = text, Style = S("Text.Body"), Margin = new Thickness(0, 0, 0, 6) }, "Brush.Text");

    /// <summary>Body text in the theme's secondary colour.</summary>
    private static TextBlock Dim(string text) => new() { Text = text, Style = S("Text.Body"), Margin = new Thickness(0, 0, 0, 6) };

    private static TextBlock Caption(string text) => new() { Text = text, Style = S("Text.Caption"), Margin = new Thickness(0, 0, 0, 6) };

    private static TextBox Sel(string text, string style = "App.SelectableText") =>
        new() { Text = text, Style = S(style), Margin = new Thickness(0, 0, 0, 4) };

    private static Button Btn(string text, Action onClick, string? tip = null, string? style = null)
    {
        var b = new Button { Content = text, ToolTip = tip, Margin = new Thickness(0, 0, 10, 8) };
        if (style != null) b.Style = S(style);
        b.Click += (_, _) => onClick();
        return b;
    }

    private static WrapPanel Buttons(params Button[] buttons)
    {
        var p = new WrapPanel { Margin = new Thickness(0, 10, 0, 2) };
        foreach (var b in buttons) p.Children.Add(b);
        return p;
    }

    private static ContentControl Tag(Origin o, string? text = null) => new()
    {
        Style = Ui.TagStyle(o), Content = text ?? OriginText.Label(o), Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center,
    };

    private static ContentControl TagStyled(string styleKey, string text) => new()
    {
        Style = S(styleKey), Content = text, VerticalAlignment = VerticalAlignment.Center,
    };

    private sealed class KvGrid
    {
        public Grid Grid { get; } = new() { Margin = new Thickness(0, 0, 0, 4) };
        public KvGrid()
        {
            Grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
            Grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        }
        public void Add(string key, string value, string? tip = null, string? brushKey = null)
        {
            var v = Sel(value);
            v.Margin = new Thickness(0, 2, 0, 2);
            if (tip != null) v.ToolTip = tip;
            if (brushKey != null) v.SetResourceReference(Control.ForegroundProperty, brushKey);
            Add(key, v);
        }
        public void Add(string key, UIElement value)
        {
            int row = Grid.RowDefinitions.Count;
            Grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var k = new TextBlock { Text = key, Style = S("Text.Caption"), Margin = new Thickness(0, 3, 10, 2) };
            Grid.SetRow(k, row); Grid.SetColumn(k, 0);
            Grid.SetRow(value, row); Grid.SetColumn(value, 1);
            Grid.Children.Add(k); Grid.Children.Add(value);
        }
    }

    private static Grid Table(string[] headers, GridLength[] widths)
    {
        var g = new Grid { Margin = new Thickness(0, 2, 0, 10) };
        foreach (var w in widths) g.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var head = new Border();
        head.SetResourceReference(Border.BackgroundProperty, "Brush.Raised");
        Grid.SetColumnSpan(head, headers.Length);
        g.Children.Add(head);
        for (int i = 0; i < headers.Length; i++)
        {
            var t = new TextBlock { Text = headers[i].ToUpperInvariant(), Style = S("Text.Section"), Margin = new Thickness(8, 6, 8, 6) };
            Grid.SetColumn(t, i);
            g.Children.Add(t);
        }
        return g;
    }

    private static void Row(Grid g, params FrameworkElement[] cells)
    {
        int row = g.RowDefinitions.Count;
        g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var line = new Border { BorderThickness = new Thickness(0, 0, 0, 1) };
        line.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");
        Grid.SetRow(line, row); Grid.SetColumnSpan(line, g.ColumnDefinitions.Count);
        g.Children.Add(line);
        for (int i = 0; i < cells.Length; i++)
        {
            var c = cells[i];
            c.Margin = new Thickness(8, 5, 8, 5);
            c.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetRow(c, row); Grid.SetColumn(c, i);
            g.Children.Add(c);
        }
    }

    private static TextBlock Cell(string text, string brushKey = "Brush.Text", string? tip = null, bool bold = false, bool mono = false)
    {
        var t = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, ToolTip = tip, FontSize = 13 };
        t.SetResourceReference(TextBlock.ForegroundProperty, brushKey);
        if (bold) t.FontWeight = FontWeights.SemiBold;
        if (mono) { t.FontFamily = (FontFamily)Application.Current.FindResource("Font.Mono"); t.FontSize = 12; }
        return t;
    }

    /// <summary>For a folder directly in the profiles folder: whose profile it is according to Windows' profile list.</summary>
    private static (string Text, bool Warn)? ProfileLine(DetailsContext c, ScanNode n)
    {
        if (!n.IsDirectory || n.Parent == null || n.Extra?.Reparse != null) return null;
        if (!c.R.Os.Paths.TryGetValue("ProfilesDir", out var pd)
            || !string.Equals(n.Parent.FullPath.TrimEnd('\\'), pd.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return null;
        var entry = c.R.Os.Profiles.FirstOrDefault(kv => string.Equals(kv.Value, n.FullPath, StringComparison.OrdinalIgnoreCase));
        if (entry.Key == null)
            return n.Name.Equals("Public", StringComparison.OrdinalIgnoreCase) || n.Name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                ? null
                : ("not in Windows' profile list — a leftover folder no account uses", true);
        var name = c.R.NameOf(entry.Key);
        var state = c.Cls.OrphanStateOf(entry.Key);
        return state == OrphanState.Proven
            ? ($"{entry.Key} — the account no longer exists; the profile list still names this folder", true)
            : ($"{name.Display}", false);
    }

    /// <summary>Who owns the objects below a folder and who is named in their explicit entries, by object count.
    /// Counts per distinct descriptor first, so a large subtree costs one walk and one look per descriptor.</summary>
    private static void AddWhoBelow(DetailsContext c, ScanNode folder, StackPanel p)
    {
        var perSd = new Dictionary<int, int>();
        int total = 0;
        var stack = new Stack<ScanNode>(folder.Children!);
        while (stack.Count > 0)
        {
            var x = stack.Pop();
            total++;
            if (x.SdIndex >= 0) perSd[x.SdIndex] = perSd.GetValueOrDefault(x.SdIndex) + 1;
            if (x.Children != null) foreach (var ch in x.Children) stack.Push(ch);
        }
        var owners = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var named = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (idx, count) in perSd)
        {
            var sd = idx < c.R.SdInfos.Length ? c.R.SdInfos[idx] : null;
            if (sd == null) continue;
            if (sd.Owner != null) owners[sd.Owner] = owners.GetValueOrDefault(sd.Owner) + count;
            foreach (var sid in sd.ExplicitDaclAces.Select(a => a.Sid).Distinct(StringComparer.OrdinalIgnoreCase))
                named[sid] = named.GetValueOrDefault(sid) + count;
        }
        if (owners.Count == 0 && named.Count == 0) return;

        p.Children.Add(Section($"Who's below ({Ui.Objects(total)})"));
        void Block(string caption, Dictionary<string, int> counts, string none)
        {
            p.Children.Add(Caption(caption));
            if (counts.Count == 0) { p.Children.Add(Dim(none)); return; }
            // count right-aligned in a narrow column, name right next to it
            var g = new Grid { Margin = new Thickness(0, 0, 0, 6) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto, MinWidth = 56 });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            int row = 0;
            foreach (var (sid, count) in counts.OrderByDescending(e => e.Value).Take(6))
            {
                var s = sid;
                g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var num = new TextBlock { Text = count.ToString("N0"), Style = S("Text.Body"), HorizontalAlignment = HorizontalAlignment.Right,
                                          VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0) };
                Grid.SetRow(num, row); g.Children.Add(num);
                var link = Link(PrincipalLabel(c, s), () => c.ShowPrincipal(s), PrincipalTip(c, s));
                link.Margin = new Thickness(-4, 0, 0, 0);
                Grid.SetRow(link, row); Grid.SetColumn(link, 1); g.Children.Add(link);
                row++;
            }
            p.Children.Add(g);
            if (counts.Count > 6) p.Children.Add(Dim($"… and {counts.Count - 6:N0} more"));
        }
        Block("Owners", owners, "No readable owners.");
        Block("Named in explicit entries", named, "Nothing below has explicit entries — everything inherits.");
    }

    /// <summary>A clickable text that behaves like a link and is reachable with the keyboard.</summary>
    private static Button Link(string text, Action onClick, string? tip = null)
    {
        var b = new Button
        {
            Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
            Style = S("Hue.Button.Ghost"), ToolTip = tip, HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(-8, 0, 0, 0),
        };
        b.Click += (_, _) => onClick();
        return b;
    }

    private static string PrincipalLabel(DetailsContext c, string sid)
    {
        var p = c.R.NameOf(sid);
        var label = p.Resolved ? p.Display : Ui.UnnamedCapability(sid) ?? c.Kb.Principal(sid)?.Name ?? sid;
        return c.Cls.IsVmGone(sid) ? label + "  (VM gone)" : label;
    }

    private static string PrincipalTip(DetailsContext c, string sid)
    {
        var e = c.Kb.Principal(sid);
        var groups = c.R.Inventory.GroupsOf(sid).Select(g => g.Name).ToList();
        var tip = sid;
        if (Classifier.VmIdOf(sid) is { } vm)
            tip += $"\nVM id {vm.ToString().ToUpperInvariant()}" + (c.Cls.IsVmGone(sid)
                ? " — no such VM on this machine any more (no <VM id>.vmcx anywhere): a leftover of a deleted VM."
                : "");
        if (e?.Explain != null) tip += "\n\n" + e.Explain;
        if (groups.Count > 0) tip += "\n\nMember of: " + string.Join(", ", groups);
        return tip + "\n\nClick to open in Accounts & groups.";
    }

    private static Path Icon(string key) => new()
    {
        Style = S("Hue.Icon"), Data = (Geometry)Application.Current.FindResource(key), Margin = new Thickness(0, 0, 8, 0),
    };

    // ---- node ---------------------------------------------------------------------------------

    public static UIElement Node(DetailsContext c, ScanNode n, bool offerReveal)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon(Ui.IconKey(n)));
        title.Children.Add(new TextBlock { Text = n.Name, Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(n.FullPath, "App.SelectableText.Dim"));
        p.Children.Add(Fg(new TextBlock { Text = Breakdown.StateLine(n, c.R), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 6) }, "Brush.Text"));

        var buttons = new List<Button>
        {
            Btn("Copy for AI", () => c.CopyNodeForAi(n), "This object with all its details, as Markdown.", "Hue.Button.Tonal"),
        };
        if (n.IsDirectory) buttons.Add(Btn("Copy for AI incl. findings below", () => c.CopySubtreeForAi(n), "This folder plus every object below it that needs attention."));
        buttons.Add(Btn("Copy path", () => c.CopyText(n.FullPath, "Path copied.")));
        if (offerReveal) buttons.Add(Btn("Show in Explorer tab", () => c.Reveal(n)));
        p.Children.Add(Buttons(buttons.ToArray()));

        // facts
        var kv = new KvGrid();
        var kind = n.Extra?.Reparse != null ? (n.IsDirectory ? "Folder (reparse point)" : "File (reparse point)") : n.IsDirectory ? "Folder" : "File";
        kv.Add("Kind", kind);
        kv.Add("Attributes", AiExport.AttrText(n.Attributes));
        if (!n.IsDirectory) kv.Add("Size", $"{Ui.Size(n.Size)} ({n.Size:N0} bytes)");
        if (!n.IsDirectory && c.R.IsLive && (((System.IO.FileAttributes)n.Attributes & (System.IO.FileAttributes.SparseFile | System.IO.FileAttributes.Compressed)) != 0))
        {
            uint low = NativeMethods.GetCompressedFileSizeW(FileProbe.Long(n.FullPath), out uint high);
            if (low != 0xFFFFFFFF || System.Runtime.InteropServices.Marshal.GetLastWin32Error() == 0)
            {
                long onDisk = ((long)high << 32) | low;
                kv.Add("On disk", $"{Ui.Size(onDisk)} ({onDisk:N0} bytes)" + (n.Size > 0 ? $" — {Math.Round(100.0 * onDisk / n.Size)} % of its size" : ""));
            }
        }
        if (n.IsDirectory && n.Children != null) kv.Add("Contains", Ui.Count(n.Children.Count(x => x.IsDirectory), "folder") + ", " + Ui.Count(n.Children.Count(x => !x.IsDirectory), "file"));
        if (n.IsDirectory && n.SubtreeAttention > 0) kv.Add("Here and below", Breakdown.Describe(n));
        if (n.ShortName != null) kv.Add("8.3 name", n.ShortName);
        if (!n.IsDirectory && n.LinkCount > 1) kv.Add("Hard links", $"{n.LinkCount} names");
        if (n.Extra?.ObjectId is Guid oid) kv.Add("Object ID", oid.ToString("B"));
        if ((n.Flags & NodeFlags.CaseSensitive) != 0) kv.Add("Case", "Case-sensitive directory");
        if ((n.Flags & NodeFlags.NotFollowed) != 0) kv.Add("Scan", "Reparse point — not followed, contents not scanned");
        if (n.Extra?.ErrorCode is int ec && ec != 0)
            kv.Add("Read error", $"{ec}: {Classifier.Win32Message(ec)} ({n.Extra.ErrorStage})", brushKey: "Brush.ErrorText");
        if (ProfileLine(c, n) is { } prof) kv.Add("Profile of", prof.Text, brushKey: prof.Warn ? "Brush.WarnText" : null);
        p.Children.Add(kv.Grid);

        // what it is (knowledge base "items")
        foreach (var item in c.Kb.ItemsFor(n).Take(2))
        {
            p.Children.Add(Section("What it is"));
            if (item.Explain != null) p.Children.Add(Dim(item.Explain));
            if (item.ShowText && !n.IsDirectory && c.R.IsLive)
            {
                var text = LiveReads.ReadStreamText(n.FullPath, ":$DATA", 4096, out var trunc, out var binary);
                p.Children.Add(Caption(binary ? "Contents (not text):" : "Contents:"));
                p.Children.Add(Sel(text.TrimEnd() + (trunc ? "\n… (first 4 KB shown)" : ""), "App.SelectableText.Mono"));
            }
            foreach (var (text, label, tag) in new (string? Text, string Label, string? Tag)[]
                     {
                         (item.How, "How to change it (the app changes nothing here):", null),
                         (item.HowReversible, "Reversible — can be switched back (the app changes nothing here):", "reversible"),
                         (item.HowFinal, "Not reversible — cannot be taken back (the app changes nothing here):", "not reversible"),
                     })
            {
                if (text == null) continue;
                var head = new WrapPanel { Margin = new Thickness(0, 8, 0, 2) };
                if (tag != null) head.Children.Add(TagStyled(tag == "reversible" ? "App.Tag.Quiet" : "Hue.Tag.Caution", tag));
                head.Children.Add(Caption(label));
                p.Children.Add(head);
                p.Children.Add(Sel(text, "App.SelectableText.Mono"));
                var copy = text;
                p.Children.Add(Buttons(Btn("Copy", () => c.CopyText(copy, "Copied."))));
            }
            p.Children.Add(Caption("Knowledge entry: items/" + item.Id));
        }

        // the component store's own action sits right under what it is, not at the end of a long panel
        if (n.IsDirectory && ComponentCleanup.IsWinSxS(c.R, n)) AddComponentCleanup(c, p);

        // findings
        p.Children.Add(Section("Findings"));
        if (n.Findings is not { Count: > 0 })
            p.Children.Add(Dim("None — this object only inherits from its parent and has no special properties."));
        else
        {
            // Explorer grants first (they are the loudest), each with its undo right under its own card.
            foreach (var f in n.Findings.OrderByDescending(f => f.Category == FindingCategory.ExplorerGrant).ThenByDescending(f => f.Origin))
            {
                p.Children.Add(FindingCard(f));
                if (f.Category != FindingCategory.ExplorerGrant || f.Detail == null) continue;
                var sid = f.Detail;
                var b = Btn($"Undo {PrincipalLabel(c, sid)}'s grant here…", () => c.StartGrantUndo(sid, n, false),
                    "Removes this one full-control entry after a preview and a backup.", "Hue.Button.Danger");
                if (c.GrantWhyNot() is { } why) { b.IsEnabled = false; b.ToolTip = why; ToolTipService.SetShowOnDisabled(b, true); }
                var row = Buttons(b, Btn($"All of {PrincipalLabel(c, sid)}'s Explorer grants…", () => c.StartGrantUndo(sid, null, false)));
                row.Margin = new Thickness(0, -6, 0, 14);
                p.Children.Add(row);
            }
        }

        AddKnown(c, n, p);

        // who's below
        if (n.IsDirectory && n.Children is { Count: > 0 }) AddWhoBelow(c, n, p);

        // security
        var sd = c.R.SdOf(n);
        p.Children.Add(Section("Security"));
        if (sd == null) p.Children.Add(Dim("The security descriptor could not be read."));
        else AddSecurity(c, n, sd, p);

        // streams
        if (n.Extra?.Streams is { Count: > 0 } streams)
        {
            p.Children.Add(Section($"Alternate data streams ({streams.Count})"));
            foreach (var s in streams)
            {
                var row = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };
                var line = new WrapPanel();
                line.Children.Add(Fg(new TextBlock { Text = s.Name, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center }, "Brush.Text"));
                line.Children.Add(new TextBlock { Text = $"{s.Size:N0} bytes", Style = S("Text.Caption"), Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center });
                var content = Sel("", "App.SelectableText.Mono");
                content.Visibility = Visibility.Collapsed;
                if (c.R.IsLive)
                {
                    var stream = s;
                    line.Children.Add(Btn("Show contents", () =>
                    {
                        var text = LiveReads.ReadStreamText(n.FullPath, stream.Name, 16 * 1024, out var trunc, out _);
                        content.Text = text + (trunc ? "\n… (first 16 KB shown)" : "");
                        content.Visibility = Visibility.Visible;
                    }));
                }
                row.Children.Add(line);
                row.Children.Add(content);
                p.Children.Add(row);
                if (s.Name.Equals(DownloadMarks.StreamName, StringComparison.OrdinalIgnoreCase))
                    AddMarkFacts(row, "What it does — and where it fails");
            }
            if (!c.R.IsLive) p.Children.Add(Caption("Contents can only be read on the machine that was scanned."));
        }

        // reparse
        if (n.Extra?.Reparse is { } rp)
        {
            p.Children.Add(Section("Reparse point"));
            var tag = c.Kb.Tag(rp.Tag);
            var rkv = new KvGrid();
            rkv.Add("Tag", $"0x{rp.Tag:X8} — {tag?.Name ?? "unknown"}");
            if (rp.PrintName != null) rkv.Add("Target", rp.PrintName);
            if (rp.SubstituteName != null && rp.SubstituteName != rp.PrintName) rkv.Add("Substitute", rp.SubstituteName);
            if (rp.Extra != null) rkv.Add("Details", rp.Extra);
            rkv.Add("Kind", rp.IsNameSurrogate ? "Name surrogate (points elsewhere; not followed)" : "Filter-owned (content handled by a driver)");
            p.Children.Add(rkv.Grid);
            if (tag?.Explain != null) p.Children.Add(Dim(tag.Explain));
        }

        // hard links
        if (!n.IsDirectory && n.LinkCount > 1 && c.R.IsLive)
        {
            p.Children.Add(Section("Hard links"));
            var list = Sel("", "App.SelectableText.Mono");
            list.Visibility = Visibility.Collapsed;
            p.Children.Add(Buttons(Btn("List all names", () =>
            {
                var names = LiveReads.HardLinkNames(n.FullPath);
                list.Text = names.Count == 0 ? "(could not list)" : string.Join("\n", names);
                list.Visibility = Visibility.Visible;
            })));
            p.Children.Add(list);
        }

        // SDDL
        if (sd != null)
        {
            p.Children.Add(Section("SDDL"));
            p.Children.Add(Sel(sd.Sddl, "App.SelectableText.Mono"));
            p.Children.Add(Buttons(Btn("Copy SDDL", () => c.CopyText(sd.Sddl, "SDDL copied."))));
        }

        // Reset to inherit — offered for folders on non-system drives
        if (n.IsDirectory && c.R.IsLive)
        {
            var whyNot = c.ResetWhyNot(n);
            if (whyNot is not ("Not on the Windows drive." or "This drive holds a Windows installation."))
            {
                p.Children.Add(Section("Reset to inherit"));
                p.Children.Add(Dim("Removes the explicit entries of this folder and everything below and lets it all inherit from "
                                   + (n.IsRoot ? "this drive root" : "the parent folder") + ". Shows a preview first; asks where to save a backup before changing anything."));
                var b = Btn("Reset to inherit…", () => c.StartReset(n));
                if (whyNot != null)
                {
                    b.IsEnabled = false;
                    b.ToolTip = whyNot;
                    ToolTipService.SetShowOnDisabled(b, true);
                    p.Children.Add(Buttons(b));
                    p.Children.Add(Caption(whyNot));
                }
                else p.Children.Add(Buttons(b));
            }
        }

        // Download marks below this folder (by location)
        if (n.IsDirectory && c.R.IsLive)
        {
            p.Children.Add(Section("Download marks"));
            p.Children.Add(Dim("Removes the download mark (Mark of the Web, the Zone.Identifier stream) from files below this "
                               + (n.IsRoot ? "drive" : "folder") + ". Shows a preview grouped by what the marks say first. Only the "
                               + "stream goes; content, other streams, security and time stamps stay."));
            p.Children.Add(Buttons(Btn("Remove download marks…", () => c.StartDownloadMarks(n))));
        }
        return p;
    }

    /// <summary>The component store: what it is, what the scan shows of older versions, and Windows' own clean-up to run.</summary>
    private static void AddComponentCleanup(DetailsContext c, StackPanel p)
    {
        p.Children.Add(Section("Component store clean-up"));
        p.Children.Add(Dim("WinSxS is Windows' component store. Most of what Windows runs lives here and is hard-linked into System32 "
            + "and the other system folders, so Explorer counts it twice. Every update adds the new version of each component it changes "
            + "and keeps the old one, so an update can be uninstalled; Windows' scheduled servicing task removes old versions only "
            + "30 days after they were superseded. Until then they sit here — and every tool that walks the disk reads them again, "
            + "virus scans included."));
        var pv = ComponentCleanup.Preview(c.R);
        if (pv != null)
        {
            var kv = new KvGrid();
            kv.Add("Older versions", pv.OlderVersions == 0 ? "none found in this scan"
                : $"{pv.OlderVersions:N0} folders of {pv.Components:N0} components have a newer version beside them");
            if (pv.OlderVersions > 0)
                kv.Add("Their content", $"{pv.Objects:N0} objects, {Ui.Size(pv.Size)} as listed — files shared with Windows through hard links count here too, so less space may be freed");
            p.Children.Add(kv.Grid);
        }
        p.Children.Add(Dim("Windows' own clean-up (dism.exe /Online /Cleanup-Image /StartComponentCleanup) removes the older versions — "
            + "the same step the scheduled task does, now instead of later. Which versions DISM removes is DISM's decision; the count "
            + "above is what the scan sees. It runs from Component store clean-up… at the top, which asks before it starts and also "
            + "works without a scan — best before a full scan, so the scan does not read what it removes."));
        p.Children.Add(Buttons(Btn("Show the clean-up button", c.PointToComponentCleanup)));
    }

    /// <summary>"Known": facts read from the disk and the system — and, for an object that differs from its stock entry,
    /// a plain line on what Windows does not record. No guesses.</summary>
    private static void AddKnown(DetailsContext c, ScanNode n, StackPanel p)
    {
        var facts = KnownFacts.For(c.R, c.Cls, n);
        bool differs = n.Findings?.Any(f => f.Category == FindingCategory.Acl && f.Origin is Origin.Modified or Origin.Differs) == true;
        if (differs) facts.AddRange(KnownFacts.InstallHistory(c.R.Os));
        if (facts.Count == 0) return;
        p.Children.Add(Section("Known"));
        var kv = new KvGrid();
        foreach (var f in facts) kv.Add(f.Key, f.Value, brushKey: f.Warn ? "Brush.ErrorText" : null);
        p.Children.Add(kv.Grid);
        if (differs)
        {
            p.Children.Add(Section("Not recorded"));
            p.Children.Add(Dim(KnownFacts.NotRecorded));
        }
        if (!c.R.IsLive) p.Children.Add(Caption("Time stamps and task definitions can only be read on the machine that was scanned."));
    }

    /// <summary>The Risks tab: where non-admins can change things in Windows-managed areas, and what runs as SYSTEM that is not
    /// Windows' own. Read-only. Unexplained entries first, in red.</summary>
    public static UIElement Risks(DetailsContext c, RiskReport rep)
    {
        var p = new StackPanel { MaxWidth = 1400, HorizontalAlignment = HorizontalAlignment.Left };
        p.Children.Add(new TextBlock { Text = "Risks", Style = S("Text.Heading"), Margin = new Thickness(0, 0, 0, 6) });
        p.Children.Add(Dim("Two read-only views of where a local privilege escalation would start. Nothing here changes anything; "
                           + "every row links to the object in the Explorer tab, where its details and knowledge entry are."));
        foreach (var note in rep.Notes) p.Children.Add(Caption(note));

        // ---- writable by non-admins
        int unexplained = rep.Writable.Count(w => w.Level == 0), ruleOnly = rep.Writable.Count(w => w.Level == 1);
        p.Children.Add(Section($"Writable by non-admins ({rep.Writable.Count:N0}: {unexplained:N0} unexplained, {ruleOnly:N0} rule only)"));
        p.Children.Add(Dim("Explicit entries under %SystemRoot%, the Program Files folders, ProgramData and on the system drive root that let "
                           + "someone other than SYSTEM, TrustedInstaller or Administrators write, create files or folders, delete, change "
                           + "permissions or take ownership — Users, Authenticated Users, Everyone, single accounts, orphaned SIDs. Write "
                           + "access in these places is the precondition for most local privilege escalations: a planted DLL, a swapped "
                           + "program, an edited task file. \"Exact entry\": a knowledge entry for this path compared the whole ACL, rights "
                           + "included. \"Rule only\": a rule knows these accounts in this area but does not compare rights — worth a look "
                           + "when the rights seem broad. \"Unexplained\" comes first. App containers (S-1-15-…) are not counted."));
        if (rep.Writable.Count == 0) p.Children.Add(Dim("None found."));
        else
        {
            var g = Table(new[] { "", "Who", "Can", "Where", "Below", "Knowledge" },
                new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto });
            foreach (var w in rep.Writable.Take(600))
            {
                var node = w.Node;
                Row(g,
                    w.Level == 2 ? TagStyled("App.Tag.Quiet", "exact entry") : w.Level == 1 ? TagStyled("Hue.Tag.Caution", "rule only") : TagStyled("Hue.Tag.Unsafe", "unexplained"),
                    Cell(PrincipalLabel(c, w.Sid), tip: w.Sid),
                    Cell(Rights.Short(w.Mask & Classifier.ControlRights) + (w.InheritOnly ? " (below only)" : ""), tip: "Full entry: " + Rights.Short(w.Mask)),
                    Link(node.FullPath, () => c.Reveal(node), "Show in the Explorer tab"),
                    Cell(w.Below > 0 ? w.Below.ToString("N0") : ""),
                    Cell(w.Finding?.KbId ?? (w.Finding != null ? OriginText.Label(w.Finding.Origin) : ""), "Brush.TextMuted"));
            }
            p.Children.Add(g);
            if (rep.Writable.Count > 600) p.Children.Add(Caption($"First 600 of {rep.Writable.Count:N0} shown."));
        }

        // ---- privileged runners
        int writableRunners = rep.Runners.Count(x => x.WritableBy.Count > 0);
        p.Children.Add(Section($"Runs as SYSTEM, not from Windows ({rep.Runners.Count:N0}, {writableRunners:N0} replaceable by non-admins)"));
        p.Children.Add(Dim("Services and scheduled tasks that run as SYSTEM, LOCAL SERVICE or NETWORK SERVICE and start a program outside the "
                           + "Windows folder (tasks: also any task outside \\Microsoft\\), plus any whose program a non-admin can change. "
                           + "Every installer that ran elevated could add one of these. The dangerous combination — SYSTEM runs something "
                           + "a user can replace — is red and comes first. Read from the registry (services) and the task definitions; "
                           + $"{rep.ServicesRead:N0} services and {rep.TasksRead:N0} tasks read."));
        if (rep.Runners.Count == 0) p.Children.Add(Dim(c.R.IsLive ? "None found." : "Not available for a snapshot."));
        else
        {
            var g = Table(new[] { "", "Kind", "Name", "Runs as", "Program", "Non-admins can" },
                new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto, new GridLength(1.4, GridUnitType.Star), new GridLength(1, GridUnitType.Star) });
            foreach (var x in rep.Runners.Take(400))
            {
                FrameworkElement program = x.Binary != null && c.R.FindByPath(x.Binary) is { } bn
                    ? Link(x.Binary, () => c.Reveal(bn), x.Command)
                    : Cell((x.Binary ?? x.Command ?? "") + (x.BinaryNotInScan ? " (not in this scan)" : ""), "Brush.TextMuted", x.Command, mono: false);
                var can = x.WritableBy.Count > 0 ? string.Join("\n", x.WritableBy) : "nothing found";
                if (x.UnquotedWithSpaces) can += "\nunquoted path with spaces";
                Row(g,
                    x.WritableBy.Count > 0 ? TagStyled("Hue.Tag.Unsafe", "replaceable") : x.UnquotedWithSpaces ? TagStyled("Hue.Tag.Caution", "check") : TagStyled("App.Tag.Quiet", "not Windows"),
                    Cell(x.Kind), Cell(x.Name), Cell(PrincipalLabel(c, x.RunsAsSid)), program,
                    Cell(can, x.WritableBy.Count > 0 ? "Brush.ErrorText" : "Brush.TextMuted"));
            }
            p.Children.Add(g);
        }

        // ---- dead tasks
        if (rep.DeadTasks.Count > 0)
        {
            p.Children.Add(Section($"Tasks that run as a deleted account ({rep.DeadTasks.Count:N0})"));
            p.Children.Add(Dim("These will never run again. Remove them through Task Scheduler (each line is the command):"));
            var lines = string.Join("\n", rep.DeadTasks.Select(d =>
            {
                var cut = d.Task.LastIndexOf('\\');
                var path = cut <= 0 ? "\\" : d.Task[..cut] + "\\";
                return $"Unregister-ScheduledTask -TaskPath '{path}' -TaskName '{d.Task[(cut + 1)..].Replace("'", "''")}' -Confirm:$false";
            }));
            p.Children.Add(Sel(lines, "App.SelectableText.Mono"));
            p.Children.Add(Buttons(Btn("Copy", () => c.CopyText(lines, "Copied."))));
        }
        return p;
    }

    /// <summary>The preview card shown before Reset to inherit writes anything.</summary>
    public static UIElement ResetPreview(DetailsContext c, ResetPlan plan, Action confirm, Action cancel)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon(Ui.IconKey(plan.Target)));
        title.Children.Add(new TextBlock { Text = "Reset to inherit — preview", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(plan.Target.FullPath, "App.SelectableText.Dim"));

        var kv = new KvGrid();
        kv.Add("Will change", $"{plan.Change.Count:N0} objects lose their explicit entries and inherit");
        kv.Add("Already inherit", $"{plan.AlreadyInheriting:N0} objects — unchanged");
        kv.Add("Left as they are", $"{plan.SkippedObjects:N0} objects ({plan.Skipped.Count:N0} places, listed below)");
        kv.Add("Not touched", "owners, auditing entries, integrity labels, links");
        if (plan.LeftAlone.Count > 0)
            kv.Add("Left alone", string.Join(", ", plan.LeftAlone) + " — another Windows installation or image (your answer)");
        p.Children.Add(kv.Grid);

        p.Children.Add(Section("Everything will inherit"));
        if (plan.Inherits.Count == 0)
            p.Children.Add(Dim("Nothing inheritable — the objects would end up with no entries at all except those Windows adds for the owner. Check the parent first."));
        else
        {
            var g = Table(new[] { "Type", "Principal", "Rights", "Applies to" },
                new[] { GridLength.Auto, new GridLength(2, GridUnitType.Star), GridLength.Auto, new GridLength(1.4, GridUnitType.Star) });
            foreach (var a in plan.Inherits)
                Row(g, a.IsDeny ? TagStyled("Hue.Tag.Caution", a.TypeName) : Cell(a.TypeName),
                    Cell(PrincipalLabel(c, a.Sid), tip: PrincipalTip(c, a.Sid)),
                    Cell(Rights.Short(a.Mask), tip: Rights.Long(a.Mask, true), mono: true),
                    Cell(Rights.AppliesTo(a.Flags, true), "Brush.TextDim"));
            p.Children.Add(g);
            p.Children.Add(Caption("Who gets what afterwards. If this is more than you want — e.g. Authenticated Users with Modify — tighten the parent first."));
        }

        if (plan.Skipped.Count > 0)
        {
            p.Children.Add(Section($"Left as they are ({plan.Skipped.Count:N0})"));
            var items = plan.Skipped.Take(2000).Select(s => new NodeItem(s.Node, $"{s.Node.FullPath}   —   {s.Reason}")).ToList();
            var lb = new ListBox { ItemsSource = items, DisplayMemberPath = "Text", MaxHeight = 240, Margin = new Thickness(0, 0, 0, 6) };
            System.Windows.Automation.AutomationProperties.SetName(lb, "Objects left as they are");
            p.Children.Add(lb);
        }

        p.Children.Add(Section("Next"));
        p.Children.Add(Dim("The next step asks where to save a backup of the current permissions (icacls format). "
                           + "Choose a place off this drive and off a USB stick you might remove. Cancelling there changes nothing."));
        var go = Btn("Choose backup file and reset…", confirm, null, "Hue.Button.Danger");
        go.IsEnabled = plan.Change.Count > 0;
        var stop = Btn("Cancel", cancel);
        p.Children.Add(Buttons(go, stop));
        if (plan.Change.Count == 0) p.Children.Add(Caption("Nothing to change — everything here already inherits."));
        return p;
    }

    public static Border FindingCard(Finding f)
    {
        var inner = new StackPanel();
        var head = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
        head.Children.Add(Tag(f.Origin));
        head.Children.Add(Fg(new TextBlock { Text = OriginText.Label(f.Category), FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) }, "Brush.Text"));
        if (f.Confidence != Confidence.None)
            head.Children.Add(new TextBlock { Text = OriginText.Label(f.Confidence), Style = S("Text.Caption"), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
        if (f.UntestedOs)
            head.Children.Add(TagStyled("Hue.Tag.Caution", "untested OS"));
        if (f.BroadDeny)
            head.Children.Add(TagStyled("Hue.Tag.Unsafe", "broad Deny"));
        inner.Children.Add(head);
        var summary = Sel(f.Summary);
        if (f.BroadDeny) summary.SetResourceReference(Control.ForegroundProperty, "Brush.ErrorText");
        inner.Children.Add(summary);
        if (f.Differences is { Count: > 0 })
            foreach (var d in f.Differences)
            {
                var t = new TextBlock { Text = "• " + d, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(8, 0, 0, 2) };
                t.SetResourceReference(TextBlock.ForegroundProperty, f.Origin == Origin.Differs ? "Brush.TextMuted" : "Brush.WarnText");
                inner.Children.Add(t);
            }
        if (!string.IsNullOrEmpty(f.Explanation)) inner.Children.Add(Dim(f.Explanation));
        // The "gap" hint only where the knowledge base is actually missing something: an undecided (Unknown) verdict.
        if (f.KbId != null) inner.Children.Add(Caption("Knowledge entry: " + f.KbId));
        else if (f.Origin == Origin.Unknown) inner.Children.Add(Caption("No knowledge entry — a gap worth sharing via Copy for AI."));
        var card = new Border { Style = S("Hue.Card"), Padding = new Thickness(14, 10, 14, 8), Margin = new Thickness(0, 0, 0, 8), Child = inner };
        return card;
    }

    private static void AddSecurity(DetailsContext c, ScanNode n, SdInfo sd, StackPanel p)
    {
        var kv = new KvGrid();
        if (sd.Owner != null) kv.Add("Owner", PrincipalLabel(c, sd.Owner), PrincipalTip(c, sd.Owner));
        if (sd.Group != null) kv.Add("Primary group", PrincipalLabel(c, sd.Group), PrincipalTip(c, sd.Group));
        kv.Add("Inheritance", sd.NullDacl ? "NULL DACL — everyone has full access" :
            sd.DaclProtected ? "Disabled (protected) — nothing flows in from the parent" : "Enabled — entries from the parent flow in",
            brushKey: sd.NullDacl ? "Brush.ErrorText" : null);
        if ((n.Flags & NodeFlags.SdIncludesSacl) == 0) kv.Add("Auditing", "SACL not readable (SeSecurityPrivilege missing or denied)");
        if (sd.Label is { } l)
            kv.Add("Integrity label", $"{Rights.LabelLevel(l.Sid)} — {Rights.LabelPolicy(l.Mask)} {Rights.InheritShort(l.Flags)}{(l.IsInherited ? " (inherited)" : " (explicit)")}",
                c.Kb.Principal(l.Sid)?.Explain);
        else kv.Add("Integrity label", "none (treated as Medium)");
        p.Children.Add(kv.Grid);

        if (sd.Dacl is { Count: > 0 })
        {
            p.Children.Add(Caption("Permissions (DACL), in evaluation order. Explicit entries in bold, inherited ones dimmed."));
            p.Children.Add(AceTable(c, n, sd.Dacl));
        }
        else if (!sd.NullDacl)
            p.Children.Add(Dim("Empty DACL — nobody has access except through privileges or ownership."));

        var audits = sd.AuditAces.ToList();
        if (audits.Count > 0)
        {
            p.Children.Add(Caption("Auditing (SACL)"));
            p.Children.Add(AceTable(c, n, audits));
        }

        AddEffectiveAccess(c, n, sd, p);
    }

    private static Grid AceTable(DetailsContext c, ScanNode n, IEnumerable<AceInfo> aces)
    {
        var g = Table(new[] { "Type", "Principal", "Rights", "Applies to", "Source" },
            new[] { GridLength.Auto, new GridLength(2, GridUnitType.Star), GridLength.Auto, new GridLength(1.4, GridUnitType.Star), new GridLength(1.4, GridUnitType.Star) });
        foreach (var a in aces)
        {
            var textKey = a.IsInherited ? "Brush.TextDim" : "Brush.Text";
            FrameworkElement type = a.IsDeny
                ? TagStyled(Rights.IsBroadDeny(a) ? "Hue.Tag.Unsafe" : "Hue.Tag.Caution", a.TypeName)
                : a.IsAudit ? TagStyled("Hue.Tag", a.TypeName) : Cell(a.TypeName, textKey);

            var sidCopy = a.Sid;
            var principal = Link(PrincipalLabel(c, a.Sid), () => c.ShowPrincipal(sidCopy), PrincipalTip(c, a.Sid));
            ((TextBlock)principal.Content).SetResourceReference(TextBlock.ForegroundProperty, textKey);
            if (!a.IsInherited) ((TextBlock)principal.Content).FontWeight = FontWeights.SemiBold;

            FrameworkElement source;
            if (a.IsInherited && AccessAnalysis.InheritedFrom(c.R, n, a) is { } from)
            {
                var target = from;
                source = Link("from " + from.FullPath, () => c.Reveal(target), "Show where this entry is set");
                ((TextBlock)((Button)source).Content).SetResourceReference(TextBlock.ForegroundProperty, "Brush.TextDim");
            }
            else source = Cell(a.IsInherited ? "inherited" : "explicit" + (a.HasCondition ? " · conditional" : ""), "Brush.TextDim");

            Row(g,
                type,
                principal,
                Cell(Rights.Short(a.Mask), textKey, $"{Rights.Long(a.Mask, n.IsDirectory)}\n{Rights.Hex(a.Mask)}", mono: true),
                Cell(Rights.AppliesTo(a.Flags, n.IsDirectory), "Brush.TextDim", Rights.InheritShort(a.Flags)),
                source);
        }
        return g;
    }

    private static void AddEffectiveAccess(DetailsContext c, ScanNode n, SdInfo sd, StackPanel p)
    {
        p.Children.Add(Section("Effective access"));
        var combo = new ComboBox { ItemsSource = c.Principals, Margin = new Thickness(0, 0, 0, 8), MaxWidth = 520, MinWidth = 320, HorizontalAlignment = HorizontalAlignment.Left };
        System.Windows.Automation.AutomationProperties.SetName(combo, "Account or group to evaluate");
        var result = new StackPanel();
        p.Children.Add(combo);
        p.Children.Add(result);
        p.Children.Add(Caption("Approximation from this object's DACL: assumes an interactive logon with an elevated token for administrators, local group memberships only, and ignores privileges such as backup/restore, share permissions and integrity levels."));

        void Show(PrincipalRowVm? pr)
        {
            result.Children.Clear();
            if (pr == null) return;
            _lastEffectiveSid = pr.Sid;
            var token = AccessAnalysis.TokenFor(c.R, pr.Sid);
            var e = AccessAnalysis.Evaluate(sd, token);
            var granted = e.Granted == 0 ? "No access" : $"{Rights.Long(e.Granted, n.IsDirectory)} ({Rights.Short(e.Granted)})";
            var g = T("Granted: " + granted);
            g.FontWeight = FontWeights.SemiBold;
            result.Children.Add(g);
            if (e.Denied != 0)
            {
                var d = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
                d.Children.Add(TagStyled("Hue.Tag.Caution", "Denied"));
                d.Children.Add(Fg(new TextBlock { Text = Rights.Long(e.Denied, n.IsDirectory), Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap }, "Brush.Text"));
                result.Children.Add(d);
            }
            if (e.NullDacl) result.Children.Add(Dim("NULL DACL — no access control."));
            if (e.OwnerImplicit) result.Children.Add(Dim("Includes the owner's implicit right to read and change permissions."));
            foreach (var ct in e.Contributions)
            {
                var via = ct.Ace.Sid == pr.Sid ? "directly" : "via " + PrincipalLabel(c, ct.Ace.Sid);
                var what = ct.Note ?? $"{(ct.Denies ? "denies" : "grants")} {Rights.Short(ct.Bits)}";
                result.Children.Add(Dim($"• entry #{ct.Ace.Index} {what} {via}{(ct.Ace.IsInherited ? " (inherited)" : "")}"));
            }
            var tokenNames = token.Where(s => s != pr.Sid).Select(s => PrincipalLabel(c, s));
            result.Children.Add(Caption("Token assumed: " + string.Join(", ", tokenNames)));
        }

        combo.SelectionChanged += (_, _) => Show(combo.SelectedItem as PrincipalRowVm);
        if (_lastEffectiveSid != null)
        {
            var prev = c.Principals.FirstOrDefault(x => x.Sid == _lastEffectiveSid);
            if (prev != null) combo.SelectedItem = prev;
        }
    }

    // ---- principal ---------------------------------------------------------------------------

    public static UIElement Principal(DetailsContext c, PrincipalRowVm pr)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Key"));
        title.Children.Add(new TextBlock { Text = pr.Name, Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(pr.Sid, "App.SelectableText.Mono"));
        p.Children.Add(Buttons(Btn("Copy for AI", () => c.CopyPrincipalForAi(pr.Sid), "The principal, where it is used explicitly, and through which groups.", "Hue.Button.Tonal")));

        var head = new WrapPanel { Margin = new Thickness(0, 4, 0, 8) };
        head.Children.Add(Tag(pr.Origin));
        head.Children.Add(new TextBlock { Text = pr.Kind, Style = S("Text.Caption"), VerticalAlignment = VerticalAlignment.Center });
        p.Children.Add(head);
        if (!string.IsNullOrEmpty(pr.Explain)) p.Children.Add(T(pr.Explain));
        p.Children.Add(Caption(pr.KbId != null ? "Knowledge entry: " + pr.KbId : "Not in the knowledge base."));

        if (pr.Orphan != OrphanState.None && c.R.Inventory.AccountTraces.TryGetValue(pr.Sid, out var traces))
        {
            p.Children.Add(Section("Where Windows still remembers it"));
            p.Children.Add(Dim("Records Windows keeps outside its account database and does not remove with the account. They grant "
                               + "nothing and are left as they are: Windows offers no supported removal for them. Read from the registry "
                               + "during this scan."));
            foreach (var t in traces) p.Children.Add(Sel(t, "App.SelectableText.Dim"));
        }

        var group = c.R.Inventory.Groups.FirstOrDefault(g => string.Equals(g.Sid, pr.Sid, StringComparison.OrdinalIgnoreCase));
        if (group != null)
        {
            p.Children.Add(Section($"Members ({group.Members.Count})"));
            if (!string.IsNullOrEmpty(group.Comment)) p.Children.Add(Dim(group.Comment));
            if (group.Members.Count == 0) p.Children.Add(Dim("(none)"));
            foreach (var m in group.Members)
            {
                var sid = m.Sid;
                p.Children.Add(Link(string.IsNullOrEmpty(m.Name) ? PrincipalLabel(c, m.Sid) : m.Name, () => c.ShowPrincipal(sid)));
            }
        }
        var memberOf = c.R.Inventory.GroupsOf(pr.Sid).ToList();
        if (memberOf.Count > 0)
        {
            p.Children.Add(Section("Member of (local groups)"));
            foreach (var g in memberOf)
                if (g.Sid != null) { var gs = g.Sid; p.Children.Add(Link(g.Name, () => c.ShowPrincipal(gs))); }
                else p.Children.Add(T(g.Name));
        }
        var user = c.R.Inventory.Users.FirstOrDefault(u => string.Equals(u.Sid, pr.Sid, StringComparison.OrdinalIgnoreCase));
        if (user != null)
        {
            var kv = new KvGrid();
            kv.Add("Account", user.Disabled ? "Disabled" : "Enabled");
            if (!string.IsNullOrEmpty(user.Comment)) kv.Add("Description", user.Comment);
            p.Children.Add(kv.Grid);
        }

        // Explorer "Continue" grants of this account
        if (pr.Sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
        {
            var grants = c.R.Findings.Count(f => f.Category == FindingCategory.ExplorerGrant
                                                 && string.Equals(f.Detail, pr.Sid, StringComparison.OrdinalIgnoreCase));
            if (grants > 0)
            {
                p.Children.Add(Section($"Explorer grants ({grants:N0})"));
                p.Children.Add(Dim($"{(grants == 1 ? "One folder carries" : $"{grants:N0} folders carry")} the exact mark of Explorer's \"Continue\": "
                                   + "full control for this account on this folder, its subfolders and files, added permanently. "
                                   + "Shows a preview first; you can leave folders out."));
                var b = Btn("Undo this account's Explorer grants…", () => c.StartGrantUndo(pr.Sid, null, true), null, "Hue.Button.Danger");
                if (c.GrantWhyNot() is { } why) { b.IsEnabled = false; b.ToolTip = why; ToolTipService.SetShowOnDisabled(b, true); }
                p.Children.Add(Buttons(b));
            }
        }

        if (pr.Orphan == OrphanState.Proven)
        {
            p.Children.Add(Section("Clean up"));
            p.Children.Add(Dim($"Replaces this SID as owner with Administrators ({Ui.Objects(pr.OwnerCount)}), removes its explicit entries "
                               + $"({Ui.Objects(pr.ExplicitCount)}) keeping every other entry, and deletes leftover folders named after it "
                               + "(Group Policy data, recycle bins). Inside %SystemRoot% it only looks and lists what it found. Shows a preview first."));
            var b = Btn("Clean up this SID…", () => c.StartCleanup(new[] { pr.Sid }));
            if (c.CleanupWhyNot() is { } why)
            {
                b.IsEnabled = false; b.ToolTip = why; ToolTipService.SetShowOnDisabled(b, true);
                p.Children.Add(Buttons(b));
                p.Children.Add(Caption(why));
            }
            else p.Children.Add(Buttons(b));
        }
        else if (pr.Orphan == OrphanState.Unverifiable)
        {
            p.Children.Add(Section("Clean up"));
            p.Children.Add(Dim("Not offered: this SID could not be checked, so it may belong to an existing account. Scan again with its domain reachable."));
        }

        var refs = c.Cls.ExplicitRefs.TryGetValue(pr.Sid, out var list) ? list : new List<ScanNode>();
        p.Children.Add(Section($"Explicit entries on {refs.Count:N0} objects"));
        if (refs.Count > 0) p.Children.Add(NodeList(c, refs, pr.Sid));

        foreach (var g in memberOf.Where(g => g.Sid != null))
        {
            if (!c.Cls.ExplicitRefs.TryGetValue(g.Sid!, out var gl) || gl.Count == 0) continue;
            p.Children.Add(Section($"Through {g.Name}: {gl.Count:N0} objects"));
            p.Children.Add(NodeList(c, gl, g.Sid!));
        }
        return p;
    }

    public sealed record NodeItem(ScanNode Node, string Text);

    /// <summary>The "Changes" page: what differs from an earlier snapshot. Most important first: new findings that
    /// need attention, then security changed on existing objects, then where objects appeared and disappeared.</summary>
    public static UIElement Changes(DetailsContext c, AclLegibility.Snapshots.SnapshotDiff d)
    {
        var p = new StackPanel { Margin = new Thickness(0, 0, 0, 24) };
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Folder"));
        title.Children.Add(new TextBlock { Text = $"Changes since {d.BaselineUtc.ToLocalTime():g}", Style = S("Text.Heading") });
        p.Children.Add(title);
        p.Children.Add(Caption($"Baseline: {d.BaselineFile} · now: scan of {d.CurrentUtc.ToLocalTime():g}"));

        var kv = new KvGrid();
        kv.Add("Compared", d.Drives.Count == 0 ? "no drive in common" : string.Join(", ", d.Drives.Select(x => x + "\\")));
        if (d.DrivesOnlyInBaseline.Count > 0) kv.Add("Only in baseline", string.Join(", ", d.DrivesOnlyInBaseline.Select(x => x + "\\")) + " — not compared");
        if (d.DrivesOnlyNow.Count > 0) kv.Add("Only now", string.Join(", ", d.DrivesOnlyNow.Select(x => x + "\\")) + " — not compared");
        kv.Add("New findings", d.NewFindings.Count == 0 ? "none" : Ui.Count(d.NewFindings.Count, "finding") + " that need attention — "
            + string.Join(", ", d.NewFindings.GroupBy(f => f.Category).OrderByDescending(g => g.Count()).Select(g => $"{OriginText.Label(g.Key)} {g.Count():N0}")),
            brushKey: d.NewFindings.Any(f => f.Origin == Origin.Modified) ? "Brush.WarnText" : null);
        kv.Add("Security changed", Ui.Objects(d.Changed.Count));
        kv.Add("Added", $"{Ui.Objects(d.Added.Count)}, {Ui.Size(d.AddedBytes)}");
        kv.Add("Removed", $"{Ui.Objects(d.Removed.Count)}, {Ui.Size(d.RemovedBytes)}");
        p.Children.Add(kv.Grid);

        if (d.NewFindings.Count > 0)
        {
            p.Children.Add(Section($"New findings that need attention ({d.NewFindings.Count:N0})"));
            p.Children.Add(List(c, d.NewFindings.OrderByDescending(f => f.Origin).ThenBy(f => f.Node.FullPath)
                .Select(f => new NodeItem(f.Node, $"{OriginText.Label(f.Origin)} · {f.KindText} · {f.Node.FullPath} — {f.Summary}")), "New findings"));
        }
        if (d.Changed.Count > 0)
        {
            p.Children.Add(Section($"Security changed ({d.Changed.Count:N0})"));
            p.Children.Add(Caption("Explicit entries, owner and inheritance on objects that exist in both scans. Inherited entries follow their source and are not listed again."));
            p.Children.Add(List(c, d.Changed.OrderBy(x => x.Node.FullPath).Select(x => new NodeItem(x.Node, $"{x.Node.FullPath} — {x.What}")), "Security changed"));
        }
        if (d.Added.Count > 0)
        {
            p.Children.Add(Section($"Added — where ({d.Added.Count:N0} objects)"));
            var folders = d.AddedByFolder.Take(200).Select(x => (Node: c.R.FindByPath(x.Folder), x)).Where(x => x.Node != null)
                .Select(x => new NodeItem(x.Node!, $"{x.x.Count,8:N0}   {x.x.Folder}   ({Ui.Size(x.x.Bytes)})"));
            p.Children.Add(List(c, folders, "Added, by folder"));
            p.Children.Add(Caption("Added, by owner:"));
            foreach (var g in d.Added.GroupBy(n => c.R.SdOf(n)?.Owner ?? "(unreadable)").OrderByDescending(g => g.Count()).Take(8))
                p.Children.Add(T($"{g.Count(),8:N0}   {(g.Key.StartsWith("S-") ? PrincipalLabel(c, g.Key) : g.Key)}"));
        }
        if (d.Removed.Count > 0)
        {
            p.Children.Add(Section($"Removed — where ({d.Removed.Count:N0} objects)"));
            var lb = new ListBox { ItemsSource = d.RemovedByFolder.Take(200).Select(x => $"{x.Count,8:N0}   {x.Folder}").ToList(), MaxHeight = 240 };
            System.Windows.Automation.AutomationProperties.SetName(lb, "Removed, by folder");
            p.Children.Add(lb);
        }
        if (d.NewFindings.Count + d.Changed.Count + d.Added.Count + d.Removed.Count == 0)
            p.Children.Add(Dim("Nothing changed on the compared drives."));
        return p;
    }

    /// <summary>The preview card shown before orphan cleanup writes anything.</summary>
    /// <param name="confirm">Whether to save the profiles' personal files as a ZIP first.</param>
    public static UIElement OrphanPreview(DetailsContext c, OrphanPlan plan, Action<bool> confirm, Action cancel)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Key"));
        title.Children.Add(new TextBlock { Text = "Clean up orphaned SIDs — preview", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);

        var kv = new KvGrid();
        kv.Add("SIDs", $"{plan.Sids.Count:N0} proven orphaned " + (plan.Sids.Count == 1 ? "SID" : "SIDs"));
        kv.Add("New owner", $"{Ui.Objects(plan.Owners.Count)} get Administrators as owner");
        kv.Add("Entries removed", $"{Ui.Objects(plan.Entries.Count)} lose their entries for these SIDs; all other entries stay");
        kv.Add("Profiles deleted", plan.Profiles.Count == 0 ? "none"
            : $"{Ui.Count(plan.Profiles.Count, "profile")} of these accounts — folder and profile-list entry, {Ui.Size(plan.Profiles.Sum(x => x.Bytes))} — cannot be undone",
            brushKey: plan.Profiles.Count > 0 ? "Brush.WarnText" : null);
        kv.Add("Folders deleted", plan.Leftovers.Count == 0 ? "none"
            : $"{plan.Leftovers.Count:N0} leftover " + (plan.Leftovers.Count == 1 ? "folder" : "folders")
              + $" named after these SIDs — {Ui.Objects(plan.Leftovers.Sum(l => l.Objects))}, {Ui.Size(plan.LeftoverBytes)} — cannot be undone",
            brushKey: plan.Leftovers.Count > 0 ? "Brush.WarnText" : null);
        kv.Add("Inside Windows", plan.Inside.Count == 0 ? "nothing unexplained found under %SystemRoot%"
            : $"{plan.Inside.Count:N0} found under %SystemRoot% — looked at, not touched (listed below)");
        if (plan.Removable.Count > 0)
            kv.Add("Explained leftovers", $"{plan.Removable.Count:N0} files under %SystemRoot% the knowledge base explains as safe to delete — only if you tick them");
        kv.Add("Not touched", "unverifiable SIDs, auditing entries, integrity labels, links, drive roots, %SystemRoot%");
        foreach (var (place, count) in plan.LeftAlone)
            kv.Add("Left alone", $"{place} — another Windows installation or image (your answer): {Ui.Objects(count)} found there, not touched");
        p.Children.Add(kv.Grid);

        if (plan.PerSid.Count > 0)
        {
            p.Children.Add(Section("Per SID"));
            var g = Table(new[] { "SID", "Owner of", "Entries on", "Folders", "In Windows" },
                new[] { new GridLength(2, GridUnitType.Star), GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto });
            foreach (var (sid, t) in plan.PerSid.OrderByDescending(x => x.Value.Owned + x.Value.WithEntries + x.Value.Folders + x.Value.Inside))
                Row(g, Cell(sid, mono: true), Cell(t.Owned.ToString("N0")), Cell(t.WithEntries.ToString("N0")),
                    Cell(t.Folders.ToString("N0")), Cell(t.Inside.ToString("N0")));
            p.Children.Add(g);
        }

        if (plan.Profiles.Count > 0)
        {
            p.Children.Add(Section($"Profiles — deleted ({plan.Profiles.Count:N0})"));
            p.Children.Add(Dim("Profiles Windows still lists for these deleted accounts. They are part of the clean-out: each goes completely — "
                               + "its folder and its entry in the profile list — through Windows' own function (as \"Account Unknown → Delete\" "
                               + "in System Properties). Personal files found in them can be saved as a ZIP first. This cannot be undone."));
            foreach (var pp in plan.Profiles)
            {
                var box = new Border { Style = S("Hue.Card"), Margin = new Thickness(0, 0, 0, 8) };
                var inner = new StackPanel();
                inner.Children.Add(T($"{pp.Path}  —  {Ui.Size(pp.Bytes)}, {Ui.Objects(pp.Objects)}"));
                inner.Children.Add(Caption(pp.Sid));
                if (pp.HasPersonal)
                {
                    var warn = T("Personal files: " + string.Join(", ", pp.Personal.OrderByDescending(x => x.Value.Bytes)
                        .Select(x => $"{x.Key} {x.Value.Count:N0} ({Ui.Size(x.Value.Bytes)})")));
                    warn.SetResourceReference(TextBlock.ForegroundProperty, "Brush.WarnText");
                    inner.Children.Add(warn);
                }
                else inner.Children.Add(Dim("No personal files found (documents, pictures, videos, audio, archives, keys) outside AppData."));
                if (pp.AppDataCount > 0)
                    inner.Children.Add(Caption($"App data: {Ui.Count(pp.AppDataCount, "file")} of those types, {Ui.Size(pp.AppDataBytes)} — not counted as personal."));
                if (pp.Node == null) inner.Children.Add(Caption("The folder is not in this scan; only the profile-list entry may be left."));
                box.Child = inner;
                p.Children.Add(box);
            }
        }

        if (plan.Leftovers.Count > 0)
        {
            p.Children.Add(Section($"Leftover folders — deleted ({plan.Leftovers.Count:N0})"));
            p.Children.Add(Dim("Folders Windows created for these accounts (Group Policy data, recycle bins, …). The accounts are gone, "
                               + "so nothing uses them. They are deleted with everything in them; this cannot be undone."));
            p.Children.Add(List(c, plan.Leftovers.Select(l => new NodeItem(l.Folder,
                $"{l.Folder.FullPath}   —   {Ui.Objects(l.Objects)}, {Ui.Size(l.Bytes)}")), "Leftover folders"));
        }

        if (plan.Entries.Count > 0)
        {
            p.Children.Add(Section("Entries removed, by drive"));
            foreach (var d in plan.EntriesByDrive)
                p.Children.Add(T($"{d.Key}  —  {Ui.Objects(d.Count())}"));
        }

        var removeBoxes = new List<(CheckBox Box, ScanNode Node)>();
        if (plan.Removable.Count > 0)
        {
            p.Children.Add(Section($"Inside Windows, explained, safe to remove ({plan.Removable.Count:N0})"));
            p.Children.Add(Dim("These are under %SystemRoot%, but the knowledge base explains why they are leftovers of the deleted "
                               + "accounts and safe to delete. None is ticked: tick the ones to delete. Deleting cannot be undone."));
            foreach (var g in plan.Removable.GroupBy(x => x.KbId))
            {
                var card = new Border { Style = S("Hue.Card"), Margin = new Thickness(0, 0, 0, 8) };
                var inner = new StackPanel();
                inner.Children.Add(Dim(g.First().Why));
                inner.Children.Add(Caption("Knowledge entry: " + g.Key));
                foreach (var (node, _, _) in g)
                {
                    var cb = new CheckBox { IsChecked = false, Content = Plain($"{node.FullPath}  —  {Ui.Size(node.Size)}") };
                    System.Windows.Automation.AutomationProperties.SetName(cb, node.FullPath);
                    inner.Children.Add(cb);
                    removeBoxes.Add((cb, node));
                }
                if (g.Count() > 1)
                {
                    var groupBoxes = removeBoxes.Where(x => g.Any(y => y.Node == x.Node)).Select(x => x.Box).ToList();
                    inner.Children.Add(Buttons(Btn("Tick all of these", () => { foreach (var b in groupBoxes) b.IsChecked = true; })));
                }
                card.Child = inner;
                p.Children.Add(card);
            }
        }

        if (plan.Inside.Count > 0)
        {
            p.Children.Add(Section($"Inside %SystemRoot% — found, not touched ({plan.Inside.Count:N0})"));
            p.Children.Add(Dim("Windows' own servicing territory. These stay exactly as they are. Copy one for AI to find out why "
                               + "it is there before deciding anything."));
            p.Children.Add(List(c, plan.Inside.Select(i => new NodeItem(i.Node, $"{i.Node.FullPath}   —   {i.What}")), "Found inside Windows, not touched"));
        }

        if (plan.Skipped.Count > 0)
        {
            p.Children.Add(Section($"Left as they are ({plan.Skipped.Count:N0})"));
            p.Children.Add(List(c, plan.Skipped.Select(s => new NodeItem(s.Node, $"{s.Node.FullPath}   —   {s.Reason}")), "Objects left as they are"));
        }

        p.Children.Add(Section("Next"));
        bool backup = plan.Entries.Count > 0;
        p.Children.Add(Dim(backup
            ? "The next step asks where to save a backup of the entries that change (icacls format, one file per drive). "
              + "Owners are not part of it — the old account no longer exists, so there is nothing to restore them to — "
              + "and deleted folders cannot be restored either. Cancelling there changes nothing."
            : "No entries change, so there is nothing to back up. Owners cannot be restored (the old account no longer exists) "
              + "and deleted folders cannot be restored either."));
        void Chosen()
        {
            plan.RemoveChosen.Clear();
            plan.RemoveChosen.AddRange(removeBoxes.Where(x => x.Box.IsChecked == true).Select(x => x.Node));
        }
        bool personal = plan.Profiles.Any(x => x.HasPersonal);
        bool AnyWork() { Chosen(); return plan.Owners.Count + plan.Entries.Count + plan.Leftovers.Count + plan.Profiles.Count > 0 || plan.RemoveChosen.Count > 0; }

        var zipGo = Btn("Back up personal files as ZIP, then clean up…", () => { Chosen(); confirm(true); },
            "Asks where to save the ZIP, writes and checks it, and deletes nothing unless that worked.", "Hue.Button.Danger");
        var plainGo = Btn(backup ? "Choose backup file and clean up…" : "Clean up", () => { Chosen(); confirm(false); }, null, "Hue.Button.Danger");
        var noZipGo = Btn("Clean up without saving personal files", () => { Chosen(); confirm(false); },
            "Deletes the profiles with their personal files. Cannot be undone.");
        var row = Buttons(zipGo, noZipGo, plainGo, Btn("Cancel", cancel));
        void Refresh()
        {
            zipGo.Visibility = personal ? Visibility.Visible : Visibility.Collapsed;
            noZipGo.Visibility = personal ? Visibility.Visible : Visibility.Collapsed;
            plainGo.Visibility = personal ? Visibility.Collapsed : Visibility.Visible;
            zipGo.IsEnabled = noZipGo.IsEnabled = plainGo.IsEnabled = AnyWork();
        }
        foreach (var (cb, _) in removeBoxes) { cb.Checked += (_, _) => Refresh(); cb.Unchecked += (_, _) => Refresh(); }
        Refresh();
        p.Children.Add(row);
        if (!plan.HasWork) p.Children.Add(Caption(plan.Inside.Count > 0 ? "Nothing to change outside %SystemRoot%." : "Nothing to change."));
        return p;
    }

    private static ListBox List(DetailsContext c, IEnumerable<NodeItem> items, string name)
    {
        var lb = new ListBox { ItemsSource = items.Take(2000).ToList(), DisplayMemberPath = "Text", MaxHeight = 240, Margin = new Thickness(0, 0, 0, 6),
                               ToolTip = "Double-click to show in the Explorer tab" };
        System.Windows.Automation.AutomationProperties.SetName(lb, name);
        lb.MouseDoubleClick += (_, _) => { if (lb.SelectedItem is NodeItem ni) c.Reveal(ni.Node); };
        return lb;
    }

    /// <summary>Preview for undoing Explorer grants: every folder with a checkbox (all ticked), what is inside
    /// %SystemRoot% (listed, not touched), then the next step. Nothing is written here.</summary>
    public static UIElement GrantPreview(DetailsContext c, GrantPlan plan, Action<IReadOnlyList<ScanNode>> confirm, Action cancel)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Key"));
        title.Children.Add(new TextBlock { Text = "Undo Explorer grants — preview", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);

        var kv = new KvGrid();
        kv.Add("Account", PrincipalLabel(c, plan.Sid));
        kv.Add("Folders", plan.Folders.Count == 0 ? "none outside %SystemRoot%"
            : $"{plan.Folders.Count:N0} — the account's one full-control entry is removed from each ticked folder");
        kv.Add("Stays", "every other entry, the owner, the protection flag; subfolders and files lose the inherited copy with it");
        kv.Add("Inside Windows", plan.Inside.Count == 0 ? "nothing under %SystemRoot%" : $"{plan.Inside.Count:N0} under %SystemRoot% — listed, not touched");
        foreach (var (place, count) in plan.LeftAlone)
            kv.Add("Left alone", $"{place} — another Windows installation or image (your answer): {Ui.Count(count, "folder")} with the mark, not touched");
        p.Children.Add(kv.Grid);

        var boxes = new List<(CheckBox Box, ScanNode Node)>();
        if (plan.Folders.Count > 0)
        {
            p.Children.Add(Section($"Folders ({plan.Folders.Count:N0})"));
            p.Children.Add(Caption("Untick a folder to keep its grant (a deliberate grant looks exactly the same). Double-click a path to show it."));
            var list = new StackPanel();
            foreach (var n in plan.Folders.Take(5000))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 2) };
                var cb = new CheckBox { IsChecked = true, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
                System.Windows.Automation.AutomationProperties.SetName(cb, n.FullPath);
                DockPanel.SetDock(cb, Dock.Left);
                row.Children.Add(cb);
                var node = n;
                var path = Link(n.FullPath, () => c.Reveal(node), "Show in the Explorer tab");
                path.Margin = new Thickness(0);
                row.Children.Add(path);
                list.Children.Add(row);
                boxes.Add((cb, n));
            }
            p.Children.Add(new ScrollViewer { Content = list, MaxHeight = 320, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 6) });
        }

        if (plan.Inside.Count > 0)
        {
            p.Children.Add(Section($"Inside %SystemRoot% — found, not touched ({plan.Inside.Count:N0})"));
            p.Children.Add(List(c, plan.Inside.Select(n => new NodeItem(n, n.FullPath)), "Found inside Windows, not touched"));
        }

        p.Children.Add(Section("Next"));
        p.Children.Add(Dim("The next step asks where to save a backup of the entries that change (icacls format, one file per drive). "
                           + "Cancelling there changes nothing."));
        var go = Btn("Choose backup file and undo…", () =>
        {
            var chosen = boxes.Where(b => b.Box.IsChecked == true).Select(b => b.Node).ToList();
            if (chosen.Count > 0) confirm(chosen);
        }, null, "Hue.Button.Danger");
        go.IsEnabled = boxes.Count > 0;
        foreach (var (cb, _) in boxes)
        {
            cb.Checked += (_, _) => go.IsEnabled = boxes.Any(b => b.Box.IsChecked == true);
            cb.Unchecked += (_, _) => go.IsEnabled = boxes.Any(b => b.Box.IsChecked == true);
        }
        p.Children.Add(Buttons(go, Btn("Cancel", cancel)));
        if (boxes.Count == 0) p.Children.Add(Caption("Nothing to change outside %SystemRoot%."));
        return p;
    }

    /// <summary>What the download mark does, where it fails, the policy and the baselines' view — no conclusion drawn.</summary>
    private static void AddMarkFacts(Panel p, string heading)
    {
        p.Children.Add(Fg(new TextBlock { Text = heading, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 2), TextWrapping = TextWrapping.Wrap }, "Brush.Text"));
        p.Children.Add(Dim(DownloadMarks.Does));
        p.Children.Add(Dim(DownloadMarks.Fails));
        p.Children.Add(Dim(DownloadMarks.Policy));
        p.Children.Add(Dim(DownloadMarks.Baselines));
    }

    /// <summary>Preview for removing download marks below a folder: one card per kind of mark on data files, each with its
    /// own tick, and one card for programs and scripts with a single tick that starts unticked. Nothing is written here.</summary>
    public static UIElement MarksPreview(MarksPlan plan, Action<IReadOnlyList<MarkedFile>> confirm, Action cancel)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Folder"));
        title.Children.Add(new TextBlock { Text = "Remove download marks — preview", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(plan.Folder.FullPath, "App.SelectableText.Dim"));
        p.Children.Add(Dim("Files below this folder that carry a download mark (Mark of the Web: the Zone.Identifier stream), grouped by "
                           + "what the mark says, read from the disk now. Removing one deletes only that stream — what the Unblock box in a "
                           + "file's Properties does, also on read-only files. Content, other streams, security, object ID and the read-only "
                           + "attribute stay; the file's time stamps are put back."));
        if (plan.Count == 0)
        {
            p.Children.Add(T("No download marks below this folder."));
            p.Children.Add(Buttons(Btn("Close", cancel)));
            return p;
        }

        var data = new List<(CheckBox Box, MarkGroup G)>();
        CheckBox? programBox = null;
        var go = Btn("Remove the ticked marks", () => { }, null, "Hue.Button.Danger");
        var count = Caption("");
        List<MarkedFile> Chosen() => data.Where(x => x.Box.IsChecked == true).SelectMany(x => x.G.Files)
            .Concat(programBox?.IsChecked == true ? plan.Programs.SelectMany(g => g.Files) : Enumerable.Empty<MarkedFile>()).ToList();
        void Refresh()
        {
            var n = Chosen().Count;
            go.IsEnabled = n > 0;
            if (n > 0) count.Text = $"{n:N0} mark{(n == 1 ? "" : "s")} will be removed.";
            else if (plan.DataCount == 0)
                count.Text = $"Nothing will be removed yet: all {plan.ProgramCount:N0} marks are on programs and scripts — tick that card to remove them.";
            else count.Text = "Nothing ticked — nothing will be removed.";
        }

        void Examples(StackPanel inner, MarkGroup g, string indent)
        {
            foreach (var f in g.Files.Take(3)) inner.Children.Add(Caption(indent + f.Node.FullPath));
            if (g.Files.Count <= 3) return;
            var all = Sel(string.Join("\n", g.Files.Take(2000).Select(f => f.Node.FullPath))
                          + (g.Files.Count > 2000 ? $"\n… and {g.Files.Count - 2000:N0} more" : ""), "App.SelectableText.Mono");
            all.Visibility = Visibility.Collapsed;
            var toggle = Btn($"Show all {g.Files.Count:N0}", () => all.Visibility = all.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible,
                null, "Hue.Button.Ghost");
            toggle.HorizontalAlignment = HorizontalAlignment.Left;
            inner.Children.Add(toggle);
            inner.Children.Add(all);
        }

        foreach (var g in plan.Groups)
        {
            var card = new Border { Style = S("Hue.Card"), Margin = new Thickness(0, 6, 0, 6) };
            var inner = new StackPanel();
            var box = new CheckBox
            {
                IsChecked = g.TickedByDefault,
                Content = Plain($"{g.Title}  —  {g.Files.Count:N0} file{(g.Files.Count == 1 ? "" : "s")}"),
            };
            box.Checked += (_, _) => Refresh();
            box.Unchecked += (_, _) => Refresh();
            inner.Children.Add(box);
            inner.Children.Add(Caption("    " + g.Explain));
            Examples(inner, g, "    ");
            card.Child = inner;
            p.Children.Add(card);
            data.Add((box, g));
        }

        if (plan.ProgramCount > 0)
        {
            var card = new Border { Style = S("Hue.Card"), Margin = new Thickness(0, 6, 0, 6) };
            var inner = new StackPanel();
            programBox = new CheckBox
            {
                IsChecked = false,
                Content = Plain($"Programs and scripts  —  {plan.ProgramCount:N0} file{(plan.ProgramCount == 1 ? "" : "s")}"),
            };
            programBox.Checked += (_, _) => Refresh();
            programBox.Unchecked += (_, _) => Refresh();
            inner.Children.Add(programBox);
            inner.Children.Add(Caption("    .exe, .dll, .msi, .cmd, .ps1, shortcuts, disk images, macro-capable Office files, … For these the mark is "
                                       + "what makes SmartScreen or Smart App Control check them before they run. Not ticked."));
            foreach (var g in plan.Programs)
            {
                inner.Children.Add(Fg(new TextBlock
                {
                    Text = $"{g.Title}  —  {g.Files.Count:N0}", FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(24, 8, 0, 2), TextWrapping = TextWrapping.Wrap,
                }, "Brush.Text"));
                Examples(inner, g, "        ");
            }
            card.Child = inner;
            p.Children.Add(card);
        }

        if (plan.Groups.Concat(plan.Programs).Any(g => g.Key == "bare"))
            p.Children.Add(Dim("Where bare marks come from: Windows' own zip handling (Extract all, or copying out of a zip opened in "
                               + "Explorer) copies an archive's mark onto the file types it treats as risky — programs, libraries, scripts, "
                               + "disk images, archives. Data files from the same archive stay unmarked. Other unpackers usually do not "
                               + "copy the mark. Unblocking the zip before extracting avoids the marks."));
        AddMarkFacts(p, "What the mark does — and where it fails");
        p.Children.Add(Section("Next"));
        p.Children.Add(Dim("Runs at once. No backup: a mark comes back only when the file is downloaded again. Afterwards the folder is "
                           + "read again and the result shows here. Cancel in the progress view stops at the next file."));
        p.Children.Add(count);
        go.Click += (_, _) => confirm(Chosen());
        p.Children.Add(Buttons(go, Btn("Cancel", cancel)));
        Refresh();
        return p;
    }

    /// <summary>Result of removing download marks: counts and every file that kept its mark, with Windows' reason.</summary>
    public static UIElement MarksResult(ScanNode folder, int asked, MarksOutcome o, Action back)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Folder"));
        title.Children.Add(new TextBlock { Text = "Remove download marks — result", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(folder.FullPath, "App.SelectableText.Dim"));
        var kv = new KvGrid();
        kv.Add("Ticked", asked.ToString("N0"));
        kv.Add("Removed", o.Removed.ToString("N0"));
        if (o.AlreadyGone > 0) kv.Add("Already gone", o.AlreadyGone.ToString("N0"));
        kv.Add("Could not be removed", o.Failed.Count.ToString("N0"));
        if (o.Cancelled) kv.Add("Stopped", "before the end — the rest keep their marks");
        p.Children.Add(kv.Grid);
        p.Children.Add(Dim("Only the Zone.Identifier stream was deleted; content, other streams, security, object ID, the read-only "
                           + "attribute and the time stamps stayed. The folder has been read again."));
        if (o.Failed.Count > 0)
        {
            p.Children.Add(Section($"Could not be removed ({o.Failed.Count:N0})"));
            foreach (var reason in o.Failed.GroupBy(f => f.Error).OrderByDescending(g => g.Count()))
            {
                p.Children.Add(Fg(new TextBlock { Text = $"{reason.Key}  —  {reason.Count():N0}", FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(0, 6, 0, 2), TextWrapping = TextWrapping.Wrap }, "Brush.Text"));
                p.Children.Add(Sel(string.Join("\n", reason.Take(5000).Select(f => f.Path))
                                   + (reason.Count() > 5000 ? $"\n… and {reason.Count() - 5000:N0} more" : ""), "App.SelectableText.Mono"));
            }
        }
        p.Children.Add(Buttons(Btn("Back to the folder", back)));
        return p;
    }

    /// <summary>A tick-box label shown as written: a plain string as Content would turn the first "_" into a keyboard
    /// shortcut marker and swallow it (package names and paths are full of underscores).</summary>
    private static TextBlock Plain(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap };

    /// <summary>Preview for the superseded app versions: what Windows answered for every older version, the unused ones
    /// (ticked: Windows removes them), the folders Windows no longer knows (none ticked: deleted) and the ones still used
    /// (listed with the reason, never touched). Needs no scan. Nothing is written here.</summary>
    public static UIElement AppVersionsPreview(AppVersionsPlan plan, Action<IReadOnlyList<AppVersionItem>, IReadOnlyList<AppVersionItem>> confirm, Action cancel)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Folder"));
        title.Children.Add(new TextBlock { Text = "Superseded app versions — preview", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(plan.WindowsApps, "App.SelectableText.Dim"));
        p.Children.Add(Dim("Older versions of app packages with a newer version of the same package beside them. DISM's component "
                           + "clean-up does not touch these. Whether one is still needed is known only to Windows' package manager, "
                           + "so it was asked (Get-AppxPackage -AllUsers, read only): which accounts use each version and which apps depend on it."));

        var used = plan.Used.ToList();
        var unused = plan.Unused.ToList();
        var staged = plan.Staged.ToList();
        var deletedOnly = plan.DeletedOnly.ToList();
        var notKnown = plan.NotKnown.ToList();
        var kv = new KvGrid();
        kv.Add("Older versions", plan.Items.Count == 0 ? "none — every package in WindowsApps is at one version" : $"{plan.Items.Count:N0}, {Ui.Size(plan.Items.Sum(i => i.Bytes))}");
        kv.Add("Staged for the system only", staged.Count == 0 ? "none" : $"{staged.Count:N0} — Windows removes them as SYSTEM, {Ui.Size(staged.Sum(i => i.Bytes))}");
        kv.Add("Only deleted accounts", deletedOnly.Count == 0 ? "none" : $"{deletedOnly.Count:N0} — Windows removes them (Remove-AppxPackage -AllUsers), {Ui.Size(deletedOnly.Sum(i => i.Bytes))}");
        kv.Add("Not known to Windows", notKnown.Count == 0 ? "none" : $"{notKnown.Count:N0} leftover folders — deleted only if you tick them, {Ui.Size(notKnown.Sum(i => i.Bytes))}");
        kv.Add("Still used", used.Count == 0 ? "none" : $"{used.Count:N0} — left alone, with the reason");
        kv.Add("Windows listed", $"{plan.Listed:N0} packages for all accounts");
        p.Children.Add(kv.Grid);
        foreach (var note in plan.Notes) p.Children.Add(Caption(note));

        CheckBox Box(AppVersionItem i, bool ticked)
        {
            var cb = new CheckBox { IsChecked = ticked, Content = Plain($"{i.FullName}  —  {Ui.Size(i.Bytes)}, {Ui.Objects(i.Objects)}"), Margin = new Thickness(0, 4, 0, 0) };
            cb.ToolTip = i.Folder;
            System.Windows.Automation.AutomationProperties.SetName(cb, i.FullName);
            return cb;
        }

        var removeBoxes = new List<(CheckBox Box, AppVersionItem Item)>();
        void Group(List<AppVersionItem> items, string heading, string text)
        {
            if (items.Count == 0) return;
            p.Children.Add(Section($"{heading} ({items.Count:N0})"));
            p.Children.Add(Dim(text));
            foreach (var i in items)
            {
                var cb = Box(i, true);
                p.Children.Add(cb);
                p.Children.Add(Caption("    " + i.Reason + $" · newest here: {i.Newest}"));
                removeBoxes.Add((cb, i));
            }
        }
        Group(staged, "Staged for the system only — Windows removes them as SYSTEM",
            "Windows keeps these ready for the system (S-1-5-18, \"Staged\"): installed for no account, and no app depends on them. "
            + "Remove-AppxPackage from an administrator does not take staged versions; run as SYSTEM it does. So the app registers a "
            + "one-off scheduled task named AclLegibility-<id> that runs as SYSTEM, removes the ticked versions, and is unregistered "
            + "again right after (leftover AclLegibility-* tasks of an interrupted run are removed first). Untick one to keep it.");
        Group(deletedOnly, "Registered only for deleted accounts — Windows removes them",
            "No existing account uses these and no app depends on them; only accounts that no longer exist still have them registered. "
            + "Each is removed by Windows with Remove-AppxPackage -AllUsers. Untick one to keep it.");

        var deleteBoxes = new List<(CheckBox Box, AppVersionItem Item)>();
        if (notKnown.Count > 0)
        {
            p.Children.Add(Section($"Not known to Windows — leftover folders ({notKnown.Count:N0})"));
            p.Children.Add(Dim("Windows lists no package by these names for any account, so its own removal cannot take them. "
                               + "None is ticked: tick the ones to delete. They are deleted with backup semantics; anything in use is "
                               + "listed and stays. Deleting cannot be undone."));
            foreach (var i in notKnown)
            {
                var cb = Box(i, false);
                p.Children.Add(cb);
                p.Children.Add(Caption("    " + i.Reason));
                deleteBoxes.Add((cb, i));
            }
        }

        if (used.Count > 0)
        {
            p.Children.Add(Section($"Still used — left alone ({used.Count:N0})"));
            var g = Table(new[] { "Package", "Version", "Why it stays" },
                new[] { new GridLength(1.2, GridUnitType.Star), GridLength.Auto, new GridLength(2, GridUnitType.Star) });
            foreach (var i in used)
                Row(g, Cell(i.Package, tip: i.FullName), Cell(i.Version.ToString(), mono: true), Cell(i.Reason, "Brush.TextDim"));
            p.Children.Add(g);
        }

        if (plan.Ghosts.Count > 0)
        {
            p.Children.Add(Section($"Registered for accounts that no longer exist ({plan.Ghosts.Count:N0})"));
            p.Children.Add(Dim("Windows still reports these packages as installed for deleted accounts. They grant nothing and are left as "
                               + "they are: Remove-AppxPackage -User refuses an account Windows cannot resolve, and -AllUsers would also "
                               + "remove the package from the accounts that use it. Windows offers no supported removal for a deleted "
                               + "account's registration; it goes with a reinstall."));
            foreach (var (sid, packages) in plan.Ghosts)
            {
                p.Children.Add(Sel(sid, "App.SelectableText.Mono"));
                foreach (var pk in packages.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) p.Children.Add(Caption("    " + pk));
            }
        }

        p.Children.Add(Section("Next"));
        p.Children.Add(Dim("Runs at once: the ticked staged versions are removed as SYSTEM (one scheduled-task run per 5), the others "
                           + "with Remove-AppxPackage -AllUsers, then the ticked leftover folders are deleted. Afterwards Windows is asked "
                           + "again and the disk is checked: only what is gone counts as removed or freed. Cancel in the progress view stops "
                           + "between steps. There is no backup: a removed version comes back only by installing it again."));
        var go = Btn("Remove the ticked versions", () =>
            confirm(removeBoxes.Where(b => b.Box.IsChecked == true).Select(b => b.Item).ToList(),
                    deleteBoxes.Where(b => b.Box.IsChecked == true).Select(b => b.Item).ToList()), null, "Hue.Button.Danger");
        void Refresh() => go.IsEnabled = removeBoxes.Any(b => b.Box.IsChecked == true) || deleteBoxes.Any(b => b.Box.IsChecked == true);
        foreach (var (cb, _) in removeBoxes.Concat(deleteBoxes)) { cb.Checked += (_, _) => Refresh(); cb.Unchecked += (_, _) => Refresh(); }
        Refresh();
        p.Children.Add(Buttons(go, Btn("Cancel", cancel)));
        if (unused.Count + notKnown.Count == 0) p.Children.Add(Caption("Nothing to remove: every older version is still used."));
        return p;
    }

    /// <summary>After the run: every version with the way it went (as SYSTEM, with -AllUsers, folder deleted), Windows'
    /// answer in plain words and what the check afterwards found. Windows' full text on demand.</summary>
    public static UIElement AppVersionsResult(AppVersionsOutcome o, int removeCount, int deleteCount)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Folder"));
        title.Children.Add(new TextBlock { Text = "Superseded app versions — result", Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Dim("What counts is the check afterwards: Windows was asked again and the disk was looked at. Windows' own \"OK\" "
                           + "is not taken as proof."));
        var kv = new KvGrid();
        if (removeCount > 0)
        {
            kv.Add("Removed and gone", o.Checked ? o.Gone.ToString("N0") : "not checked");
            kv.Add("Folder still on disk", o.Checked ? o.OnDisk.ToString("N0") : "not checked");
            kv.Add("Not removed", o.Checked ? o.NotRemoved.ToString("N0") : "not checked");
        }
        if (deleteCount > 0) kv.Add("Leftover folders deleted", $"{o.FoldersDeleted:N0} of {deleteCount:N0}");
        kv.Add("Freed", o.BytesFreed > 0 ? Ui.Size(o.BytesFreed) + " — only what is gone from disk" : "nothing");
        if (o.Cancelled) kv.Add("Stopped", "before the end — the rest is unchanged");
        p.Children.Add(kv.Grid);

        void Lines(IEnumerable<AppVersionResult> rs, string heading)
        {
            var list = rs.ToList();
            if (list.Count == 0) return;
            p.Children.Add(Section($"{heading} ({list.Count:N0})"));
            foreach (var r in list)
            {
                p.Children.Add(Sel(r.Item.FullName, "App.SelectableText.Mono"));
                p.Children.Add(Caption($"    {r.RouteText} · Windows answered: {r.Answer} · {r.Status}"));
                if (r.Full is { Length: > 0 } full)
                {
                    var box = Sel(full, "App.SelectableText.Dim");
                    box.Visibility = Visibility.Collapsed;
                    box.Margin = new Thickness(16, 0, 0, 6);
                    var toggle = Btn("Windows' full answer", () => box.Visibility = box.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible,
                        null, "Hue.Button.Ghost");
                    toggle.Margin = new Thickness(12, 0, 0, 4);
                    toggle.HorizontalAlignment = HorizontalAlignment.Left;
                    p.Children.Add(toggle);
                    p.Children.Add(box);
                }
            }
        }
        Lines(o.Results.Where(r => !r.Gone && r.Route != AppRoute.DeleteFolder), "Not removed or still on disk");
        Lines(o.Results.Where(r => !r.Gone && r.Route == AppRoute.DeleteFolder), "Leftover folders not fully deleted");
        Lines(o.Results.Where(r => r.Gone), "Removed and gone");
        if (o.Failed.Count > 0)
        {
            p.Children.Add(Section("Notes"));
            foreach (var (what, error) in o.Failed) p.Children.Add(Caption($"{what} — {error}"));
        }
        p.Children.Add(Caption("Nothing here can be restored by the app; a removed app version comes back only by installing it again."));
        return p;
    }

    private static ListBox NodeList(DetailsContext c, List<ScanNode> nodes, string sid)
    {
        const int cap = 20000;
        var items = nodes.Take(cap).Select(nd =>
        {
            var sd = c.R.SdOf(nd);
            var aces = sd?.Dacl?.Where(a => !a.IsInherited && a.Sid == sid).Select(a => $"{(a.IsDeny ? "DENY " : "")}{Rights.Short(a.Mask)}") ?? Enumerable.Empty<string>();
            return new NodeItem(nd, $"{nd.FullPath}   —   {string.Join(", ", aces)}");
        }).ToList();
        var lb = new ListBox
        {
            ItemsSource = items, DisplayMemberPath = "Text", MaxHeight = 320, Margin = new Thickness(0, 0, 0, 6),
            ToolTip = "Double-click or Enter to show in the Explorer tab",
        };
        VirtualizingPanel.SetIsVirtualizing(lb, true);
        System.Windows.Automation.AutomationProperties.SetName(lb, "Objects with explicit entries");
        lb.MouseDoubleClick += (_, _) => { if (lb.SelectedItem is NodeItem ni) c.Reveal(ni.Node); };
        lb.KeyDown += (_, e) => { if (e.Key == Key.Enter && lb.SelectedItem is NodeItem ni) c.Reveal(ni.Node); };
        return lb;
    }

    // ---- share -------------------------------------------------------------------------------

    public static UIElement Share(DetailsContext c, ShareRowVm s)
    {
        var p = new StackPanel();
        var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        title.Children.Add(Icon("Icon.Network"));
        title.Children.Add(new TextBlock { Text = s.Name, Style = S("Text.Heading"), TextWrapping = TextWrapping.Wrap });
        p.Children.Add(title);
        p.Children.Add(Sel(s.Path, "App.SelectableText.Dim"));
        var head = new WrapPanel { Margin = new Thickness(0, 4, 0, 8) };
        head.Children.Add(Tag(s.Origin));
        head.Children.Add(new TextBlock { Text = OriginText.Label(s.Confidence), Style = S("Text.Caption"), VerticalAlignment = VerticalAlignment.Center });
        p.Children.Add(head);
        if (!string.IsNullOrEmpty(s.Explain)) p.Children.Add(T(s.Explain));

        var kv = new KvGrid();
        kv.Add("Type", s.TypeText);
        if (!string.IsNullOrEmpty(s.Remark)) kv.Add("Remark", s.Remark);
        p.Children.Add(kv.Grid);

        p.Children.Add(Section("Share permissions"));
        if (s.Share.SecurityDescriptor == null)
            p.Children.Add(Dim("No descriptor stored — the share uses the default (administrative shares are limited to administrators by the Server service)."));
        else
        {
            var sd = new SdInfo(s.Share.SecurityDescriptor);
            if (sd.Dacl == null) p.Children.Add(Dim("NULL DACL — everyone has full access at share level."));
            else
            {
                var g = Table(new[] { "Type", "Principal", "Share access" }, new[] { GridLength.Auto, new GridLength(2, GridUnitType.Star), new GridLength(1, GridUnitType.Star) });
                foreach (var a in sd.Dacl)
                {
                    var sid = a.Sid;
                    FrameworkElement type = a.IsDeny ? TagStyled("Hue.Tag.Caution", a.TypeName) : Cell(a.TypeName);
                    Row(g, type, Link(PrincipalLabel(c, a.Sid), () => c.ShowPrincipal(sid), PrincipalTip(c, a.Sid)), Cell(AiExport.ShareRights(a.Mask)));
                }
                p.Children.Add(g);
            }
            p.Children.Add(Caption("Effective access over the network is the more restrictive of share and NTFS permissions."));
            p.Children.Add(Section("SDDL"));
            p.Children.Add(Sel(sd.Sddl, "App.SelectableText.Mono"));
        }

        if (!string.IsNullOrEmpty(s.Path) && c.R.FindByPath(s.Path) is { } node)
        {
            p.Children.Add(Section("Folder (NTFS)"));
            p.Children.Add(Buttons(Btn("Show folder in Explorer tab", () => c.Reveal(node))));
        }
        return p;
    }
}
