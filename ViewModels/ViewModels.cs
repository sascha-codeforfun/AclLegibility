using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Security;
using AclLegibility.Theme;

namespace AclLegibility.ViewModels;

// View models expose origins and resource keys, never brushes: the theme resolves colours,
// so a Windows contrast theme can swap them (HueTheme rule 2).

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    protected void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value; Raise(name); return true;
    }
}

/// <summary>Directory node in the tree; children load on expand.</summary>
public sealed class TreeItemVm : ObservableObject
{
    private static readonly TreeItemVm Placeholder = new(new ScanNode { Name = "…" }, null);
    private readonly Func<bool> _onlyAttention;
    public ScanNode Node { get; }
    public TreeItemVm? ParentVm { get; }
    public ObservableCollection<TreeItemVm> Children { get; } = new();
    private bool _loaded;

    private TreeItemVm(ScanNode node, TreeItemVm? parent) { Node = node; ParentVm = parent; _onlyAttention = () => false; }

    public TreeItemVm(ScanNode node, TreeItemVm? parent, Func<bool> onlyAttention)
    {
        Node = node; ParentVm = parent; _onlyAttention = onlyAttention;
        if (HasDirChildren()) Children.Add(Placeholder);
    }

    private bool HasDirChildren() => Node.Children?.Any(c => c.IsDirectory && Visible(c)) == true;
    /// <summary>Links stay visible with "Only needs attention" on, stock ones included.</summary>
    private bool Visible(ScanNode c) => !_onlyAttention() || c.SubtreeAttention > 0 || c.SubtreeLinks > 0;

    public string Name => Node.Name;
    public string IconKey => Ui.IconKey(Node);
    public string Link => Ui.LinkLook(Node);
    /// <summary>Red pill: objects below whose worst finding is Modified. Shown only when there are any.</summary>
    public bool HasModified => Node.SubtreeModified > 0;
    /// <summary>This folder itself holds an explicit Deny for a broad group.</summary>
    public bool HasBroadDeny => Node.Findings?.Any(f => f.BroadDeny) == true;
    public string ModifiedBadge => $"{Node.SubtreeModified:N0} modified below";
    /// <summary>Second pill: everything else that needs attention, coloured by its own worst origin.</summary>
    public bool HasRest => Node.SubtreeAttention - Node.SubtreeModified > 0;
    public string RestBadge => (Node.SubtreeAttention - Node.SubtreeModified).ToString("N0");
    public Origin RestWorst => Node.SubtreeWorstRest;

    private string? _toolTip;
    public string ToolTip => _toolTip ??= Breakdown.Describe(Node);

    private bool _isExpanded;
    public bool IsExpanded
    {
        get => _isExpanded;
        set { if (Set(ref _isExpanded, value) && value) EnsureChildren(); }
    }

    private bool _isSelected;
    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }

    public void EnsureChildren()
    {
        if (_loaded) return;
        _loaded = true;
        Children.Clear();
        if (Node.Children == null) return;
        foreach (var c in Node.Children)
            if (c.IsDirectory && Visible(c)) Children.Add(new TreeItemVm(c, this, _onlyAttention));
    }

    public static Origin OwnWorst(ScanNode n) => n.Findings?.Select(f => f.Origin).DefaultIfEmpty(Origin.None).Max() ?? Origin.None;
}

/// <summary>What is below a folder, for the badge tooltip: objects by worst origin, findings by category.</summary>
public static class Breakdown
{
    /// <summary>Objects here and below that need attention, by their worst origin.</summary>
    public static Dictionary<Origin, int> ByOrigin(ScanNode root)
    {
        var byOrigin = new Dictionary<Origin, int>();
        var stack = new Stack<ScanNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n.SubtreeAttention == 0 && n != root) continue;
            var worst = Origin.None;
            if (n.Findings != null)
                foreach (var f in n.Findings)
                    if (f.NeedsAttention && f.Origin > worst) worst = f.Origin;
            if (worst != Origin.None) byOrigin[worst] = byOrigin.GetValueOrDefault(worst) + 1;
            if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
        }
        return byOrigin;
    }

    /// <summary>One line that keeps the object's own state apart from what is below it:
    /// "This folder: Stock · Below: 6 modified, 183 unknown, 1 custom".</summary>
    public static string StateLine(ScanNode n, ScanResult r)
    {
        var own = TreeItemVm.OwnWorst(n);
        var ownText = own == Origin.None ? NodeRowVm.NoFindingLabel(n, r) : OriginText.Label(own);
        var line = (n.IsRoot && (n.Flags & NodeFlags.IsVolumeRoot) != 0 ? "This drive root: " : n.IsDirectory ? "This folder: " : "This file: ") + ownText;
        if (!n.IsDirectory) return line;
        var below = ByOrigin(n);
        // The object's own worst origin is counted in ByOrigin too; take it out so "below" means strictly below.
        var ownAttention = n.Findings?.Where(f => f.NeedsAttention).Select(f => f.Origin).DefaultIfEmpty(Origin.None).Max() ?? Origin.None;
        if (ownAttention != Origin.None && below.TryGetValue(ownAttention, out var c0)) { if (c0 <= 1) below.Remove(ownAttention); else below[ownAttention] = c0 - 1; }
        var parts = new[] { Origin.Modified, Origin.Custom, Origin.Unknown }
            .Where(below.ContainsKey).Select(o => $"{below[o]:N0} {(o == Origin.Modified ? "modified" : OriginText.Label(o).ToLowerInvariant())}").ToList();
        return line + " · Below: " + (parts.Count == 0 ? "nothing needs attention" : string.Join(", ", parts));
    }

    public static string Describe(ScanNode root)
    {
        if (root.SubtreeAttention == 0) return "Nothing below needs attention (only stock and traces).";
        var byOrigin = new Dictionary<Origin, int>();
        var byCategory = new Dictionary<FindingCategory, int>();
        var stack = new Stack<ScanNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n.SubtreeAttention == 0 && n != root) continue;
            if (n.Findings != null)
            {
                var worst = Origin.None;
                foreach (var f in n.Findings)
                {
                    if (!f.NeedsAttention) continue;
                    if (f.Origin > worst) worst = f.Origin;
                    byCategory[f.Category] = byCategory.GetValueOrDefault(f.Category) + 1;
                }
                if (worst != Origin.None) byOrigin[worst] = byOrigin.GetValueOrDefault(worst) + 1;
            }
            if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
        }
        var sb = new StringBuilder();
        if (root.SubtreeModified > 0) sb.Append($"{root.SubtreeModified:N0} of {root.SubtreeAttention:N0} modified · ");
        sb.Append(root.SubtreeAttention == 1 ? "1 object here and below needs attention" : $"{root.SubtreeAttention:N0} objects here and below need attention");
        foreach (var o in new[] { Origin.Modified, Origin.Custom, Origin.Unknown })
            if (byOrigin.TryGetValue(o, out var c)) sb.Append($"\n  {OriginText.Label(o)}: {c:N0}");
        sb.Append("\nFindings by kind:");
        foreach (var kv in byCategory.OrderByDescending(k => k.Value))
            sb.Append($"\n  {OriginText.Label(kv.Key)}: {kv.Value:N0}");
        return sb.ToString();
    }
}

/// <summary>Row of the folder content list.</summary>
public sealed class NodeRowVm
{
    public ScanNode Node { get; }
    private readonly ScanResult _r;
    public NodeRowVm(ScanNode n, ScanResult r) { Node = n; _r = r; }

    public string IconKey => Ui.IconKey(Node);
    public string Name => Node.Name;
    public string Link => Ui.LinkLook(Node);
    public Origin Origin => TreeItemVm.OwnWorst(Node);
    /// <summary>The object's own state only — what is below is in the Below column and the tree pills.
    /// Without a finding of its own: "inherits", or "as parent" when it repeats its parent's explicit entries.</summary>
    public string OriginLabel => Origin == Origin.None ? NoFindingLabel(Node, _r) : OriginText.Label(Origin);
    public bool HasOrigin => true;

    public static string NoFindingLabel(ScanNode n, ScanResult r) =>
        r.SdOf(n) is { IsBreakpoint: true } ? "as parent" : "inherits";
    public bool BroadDeny => Node.Findings?.Any(f => f.BroadDeny) == true;
    public string FindingsText => Node.Findings == null ? "" :
        string.Join(", ", Node.Findings.Select(f => f.KindText).Distinct());
    public string Below => Node.IsDirectory && Node.SubtreeAttention > 0 ? Node.SubtreeAttention.ToString("N0") : "";
    public string Owner
    {
        get
        {
            var sd = _r.SdOf(Node);
            if (sd?.Owner == null) return "";
            var p = _r.NameOf(sd.Owner);
            return p.Resolved ? p.Name! : sd.Owner;
        }
    }
    public string SizeText => Node.IsDirectory ? "" : Ui.Size(Node.Size);
}

public sealed class FindingRowVm
{
    public Finding Finding { get; }
    public FindingRowVm(Finding f) { Finding = f; }
    public Origin Origin => Finding.Origin;
    public string OriginLabel => OriginText.Label(Finding.Origin);
    public string Category => Finding.KindText;
    public bool BroadDeny => Finding.BroadDeny;
    private string? _path;
    public string Path => _path ??= Finding.Node.FullPath;
    public string Summary => Finding.Summary;
    public string KbId => Finding.KbId ?? "";
    public string Confidence => OriginText.Label(Finding.Confidence) + (Finding.UntestedOs ? " · untested OS" : "");
}

public sealed class PrincipalRowVm
{
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public string Kind { get; init; } = "";
    public Origin Origin { get; init; }
    public int ExplicitCount { get; init; }
    public int OwnerCount { get; init; }
    public OrphanState Orphan { get; init; }
    public string Explain { get; init; } = "";
    public string? KbId { get; init; }
    public string OriginLabel => OriginText.Label(Origin);
    public string ExplicitText => ExplicitCount > 0 ? ExplicitCount.ToString("N0") : "";
    public string OwnerText => OwnerCount > 0 ? OwnerCount.ToString("N0") : "";
    public override string ToString() => Name == Sid ? Sid : $"{Name}  ({Kind})";
}

public sealed class ShareRowVm
{
    public ShareEntry Share { get; init; } = null!;
    public Origin Origin { get; init; }
    public string Explain { get; init; } = "";
    public string? KbId { get; init; }
    public Confidence Confidence { get; init; }
    public string Name => Share.Name;
    public string Path => Share.Path ?? "";
    public string TypeText => Share.TypeText;
    public string Remark => Share.Remark ?? "";
    public string OriginLabel => OriginText.Label(Origin);
}

public static class PrincipalKinds
{
    public static string Describe(string sid, PrincipalName p, ScanResult r, CompiledKb kb, OrphanState orphan)
    {
        if (orphan == OrphanState.Proven) return "Orphaned SID";
        if (orphan == OrphanState.Unverifiable) return "Unverifiable SID";
        if (sid.StartsWith("S-1-5-82-", StringComparison.Ordinal)) return "IIS app pool";
        if (sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) return "Service";
        if (sid.StartsWith("S-1-15-3-", StringComparison.Ordinal)) return "Capability";
        if (sid.StartsWith("S-1-15-2-", StringComparison.Ordinal)) return "App package";
        if (sid.StartsWith("S-1-16-", StringComparison.Ordinal)) return "Integrity level";
        if (sid.StartsWith("S-1-5-32-", StringComparison.Ordinal)) return "Built-in group";
        if (SidText.SplitAccountSid(sid) is { } split)
        {
            bool local = string.Equals(split.Prefix, r.Os.MachineSid, StringComparison.OrdinalIgnoreCase);
            var scope = local ? "Local" : "Domain";
            return p.Use switch
            {
                SidUse.User => $"{scope} user",
                SidUse.Group or SidUse.Alias or SidUse.WellKnownGroup => $"{scope} group",
                SidUse.Computer => $"{scope} computer",
                SidUse.DeletedAccount => "Deleted account",
                _ => p.Resolved ? scope : "Orphaned SID",
            };
        }
        if (!p.Resolved && kb.Principal(sid) == null) return "Unresolved";
        return "Well-known";
    }
}
