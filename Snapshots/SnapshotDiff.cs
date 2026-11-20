using System;
using System.Collections.Generic;
using System.Linq;
using AclLegibility.Model;
using AclLegibility.Security;

namespace AclLegibility.Snapshots;

/// <summary>A change in security between two scans of the same path.</summary>
public sealed record SecurityChange(ScanNode Node, string What);

/// <summary>
/// What changed between an earlier snapshot (the baseline) and the current scan: objects added and removed,
/// security changed on the same path, and findings that need attention now but did not before. Only drives
/// present in both are compared, so a baseline of fewer drives produces no noise.
/// </summary>
public sealed class SnapshotDiff
{
    public required string BaselineFile { get; init; }
    public required DateTime BaselineUtc { get; init; }
    public required DateTime CurrentUtc { get; init; }
    public List<string> Drives { get; } = new();
    public List<string> DrivesOnlyInBaseline { get; } = new();
    public List<string> DrivesOnlyNow { get; } = new();
    public List<ScanNode> Added { get; } = new();
    public List<(string Path, bool IsDirectory, string? Owner)> Removed { get; } = new();
    public List<SecurityChange> Changed { get; } = new();
    public List<Finding> NewFindings { get; } = new();
    public long AddedBytes { get; set; }
    public long RemovedBytes { get; set; }

    /// <summary>Added objects grouped by the folder they appeared in (top-most new folder counts as one place).</summary>
    public IEnumerable<(string Folder, int Count, long Bytes)> AddedByFolder =>
        Added.GroupBy(n => n.Parent?.FullPath ?? n.FullPath, StringComparer.OrdinalIgnoreCase)
             .Select(g => (g.Key, g.Count(), g.Where(x => !x.IsDirectory).Sum(x => x.Size)))
             .OrderByDescending(x => x.Item2);

    public IEnumerable<(string Folder, int Count)> RemovedByFolder =>
        Removed.GroupBy(x => Parent(x.Path), StringComparer.OrdinalIgnoreCase)
               .Select(g => (g.Key, g.Count())).OrderByDescending(x => x.Item2);

    private static string Parent(string p) { var i = p.TrimEnd('\\').LastIndexOf('\\'); return i <= 2 ? p[..Math.Min(p.Length, 3)] : p[..i]; }

    public static SnapshotDiff Compute(string baselineFile, ScanResult baseline, ScanResult current, Action<string>? say = null)
    {
        string Name(string? sid) => sid == null ? "(none)" : current.NameOf(sid).Resolved ? current.NameOf(sid).Display : baseline.NameOf(sid).Display;
        var d = new SnapshotDiff { BaselineFile = baselineFile, BaselineUtc = baseline.ScannedUtc, CurrentUtc = current.ScannedUtc };
        static string Drive(ScanNode r) => r.Name.TrimEnd('\\').ToUpperInvariant();
        var baseRoots = baseline.Roots.ToDictionary(Drive, StringComparer.OrdinalIgnoreCase);
        var curRoots = current.Roots.ToDictionary(Drive, StringComparer.OrdinalIgnoreCase);
        d.Drives.AddRange(curRoots.Keys.Where(baseRoots.ContainsKey).OrderBy(x => x));
        d.DrivesOnlyInBaseline.AddRange(baseRoots.Keys.Where(k => !curRoots.ContainsKey(k)).OrderBy(x => x));
        d.DrivesOnlyNow.AddRange(curRoots.Keys.Where(k => !baseRoots.ContainsKey(k)).OrderBy(x => x));

        foreach (var drive in d.Drives)
        {
            say?.Invoke($"Comparing {drive}\\ …");
            var before = new Dictionary<string, ScanNode>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in Walk(baseRoots[drive])) before[n.FullPath] = n;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in Walk(curRoots[drive]))
            {
                var path = n.FullPath;
                if (!before.TryGetValue(path, out var old))
                {
                    // report the top-most new object only once per new subtree? No: every object counts, grouping shows where.
                    d.Added.Add(n);
                    if (!n.IsDirectory) d.AddedBytes += n.Size;
                    continue;
                }
                seen.Add(path);
                if (Describe(baseline.SdOf(old), current.SdOf(n), Name) is { } what) d.Changed.Add(new SecurityChange(n, what));
            }
            foreach (var (path, old) in before)
            {
                if (seen.Contains(path)) continue;
                d.Removed.Add((path, old.IsDirectory, baseline.SdOf(old)?.Owner));
                if (!old.IsDirectory) d.RemovedBytes += old.Size;
            }
        }

        say?.Invoke("Comparing findings…");
        var drives = new HashSet<string>(d.Drives, StringComparer.OrdinalIgnoreCase);
        static string Key(Finding f) => $"{f.Node.FullPath}|{f.Category}|{f.Detail}|{f.Origin}";
        var before2 = new HashSet<string>(baseline.Findings.Where(f => f.NeedsAttention).Select(Key), StringComparer.OrdinalIgnoreCase);
        foreach (var f in current.Findings.Where(f => f.NeedsAttention))
        {
            var drive = f.Node.FullPath.Length >= 2 ? f.Node.FullPath[..2].ToUpperInvariant() : "";
            if (drives.Contains(drive) && !before2.Contains(Key(f))) d.NewFindings.Add(f);
        }
        return d;
    }

    private static IEnumerable<ScanNode> Walk(ScanNode root)
    {
        var stack = new Stack<ScanNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            yield return n;
            if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
        }
    }

    /// <summary>Owner, protection and explicit entries before → after; null when the security is the same.</summary>
    private static string? Describe(SdInfo? a, SdInfo? b, Func<string?, string> name)
    {
        if (a == null || b == null) return a == null && b == null ? null : (a == null ? "became readable" : "became unreadable");
        var parts = new List<string>();
        if (!string.Equals(a.Owner, b.Owner, StringComparison.OrdinalIgnoreCase)) parts.Add($"owner {name(a.Owner)} → {name(b.Owner)}");
        if (a.DaclProtected != b.DaclProtected) parts.Add(b.DaclProtected ? "inheritance turned off" : "inheritance turned on");
        string Ace(AceInfo x) => $"{(x.IsDeny ? "deny" : "allow")} {x.Sid} 0x{x.NormalizedMask:x} {x.Flags}";
        var ea = a.ExplicitDaclAces.ToList();
        var eb = b.ExplicitDaclAces.ToList();
        var keysA = new HashSet<string>(ea.Select(Ace), StringComparer.OrdinalIgnoreCase);
        var keysB = new HashSet<string>(eb.Select(Ace), StringComparer.OrdinalIgnoreCase);
        foreach (var x in eb.Where(x => !keysA.Contains(Ace(x))).Take(4)) parts.Add($"+ {(x.IsDeny ? "deny" : "allow")} {name(x.Sid)}");
        foreach (var x in ea.Where(x => !keysB.Contains(Ace(x))).Take(4)) parts.Add($"− {(x.IsDeny ? "deny" : "allow")} {name(x.Sid)}");
        return parts.Count == 0 ? null : string.Join(", ", parts);
    }
}
