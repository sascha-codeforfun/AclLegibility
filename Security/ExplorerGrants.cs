using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Native;

namespace AclLegibility.Security;

/// <summary>What undoing an account's Explorer grants would do.</summary>
public sealed class GrantPlan
{
    public required string Sid { get; init; }
    /// <summary>Folders carrying the mark, outside %SystemRoot% — offered for undo (the user may leave some out).</summary>
    public List<ScanNode> Folders { get; } = new();
    /// <summary>Folders carrying the mark inside %SystemRoot% — listed, not touched.</summary>
    public List<ScanNode> Inside { get; } = new();
    /// <summary>Places you said hold another Windows installation or image: folders there are left alone (counted).</summary>
    public Dictionary<string, int> LeftAlone { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record GrantOutcome(int Changed, List<(string Path, int Error)> Failed, bool Cancelled);

/// <summary>
/// Undoes Explorer's "Continue" grants for one account: removes that account's single full-control
/// (OI)(CI) entry from each chosen folder. Every other entry, the owner and the protection flag stay;
/// the children lose the inherited copy with it. Nothing under %SystemRoot% is changed. The entries are
/// backed up in icacls format (one file per drive) before the first change.
/// </summary>
public static class ExplorerGrants
{
    public static string? WhyNot(ScanResult r)
    {
        if (!r.IsLive) return "Only on a live scan of this machine, not on a snapshot.";
        if (r.Cancelled) return "The scan was cancelled, so it may be incomplete. Scan again first.";
        return null;
    }

    /// <summary>All folders with the mark for this account, or only <paramref name="only"/> when given.</summary>
    public static GrantPlan Plan(ScanResult r, Classifier cls, string sid, ScanNode? only = null, IReadOnlyCollection<string>? leaveAlone = null)
    {
        var plan = new GrantPlan { Sid = sid };
        r.Os.Paths.TryGetValue("SystemRoot", out var sysRoot);
        bool InSystemRoot(ScanNode n) => sysRoot != null &&
            (n.FullPath.Equals(sysRoot, StringComparison.OrdinalIgnoreCase)
             || n.FullPath.StartsWith(sysRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
        IEnumerable<ScanNode> candidates = only != null ? new[] { only } : r.AllNodes();
        foreach (var n in candidates)
        {
            if (!n.IsDirectory || r.SdOf(n) is not { } sd) continue;
            if (!cls.ExplorerGrantSids(n, sd).Contains(sid, StringComparer.OrdinalIgnoreCase)) continue;
            if (ForeignWindows.HolderOf(n.FullPath, leaveAlone) is { } holder)
            {
                plan.LeftAlone[holder] = plan.LeftAlone.GetValueOrDefault(holder) + 1;
                continue;
            }
            (InSystemRoot(n) ? plan.Inside : plan.Folders).Add(n);
        }
        return plan;
    }

    public static List<(string Drive, string File, IReadOnlyList<ScanNode> Nodes)> BackupFiles(IReadOnlyList<ScanNode> folders, string chosen)
    {
        var groups = folders.GroupBy(n => ResetToInherit.VolumeOf(n.FullPath), StringComparer.OrdinalIgnoreCase).ToList();
        var result = new List<(string, string, IReadOnlyList<ScanNode>)>();
        foreach (var g in groups)
        {
            var file = groups.Count == 1 ? chosen
                : Path.Combine(Path.GetDirectoryName(chosen) ?? "", Path.GetFileNameWithoutExtension(chosen) + "-" + g.Key.TrimEnd('\\', ':') + Path.GetExtension(chosen));
            result.Add((g.Key, file, g.ToList()));
        }
        return result;
    }

    public static void WriteBackups(ScanResult r, IReadOnlyList<ScanNode> folders, string chosen)
    {
        foreach (var (drive, file, nodes) in BackupFiles(folders, chosen))
            IcaclsBackup.Write(r, nodes, drive, file);
    }

    public static GrantOutcome Run(ScanResult r, string sid, IReadOnlyList<ScanNode> folders, Action<int, int, string> progress, CancellationToken ct)
    {
        Privileges.Enable(Privileges.Restore);
        Privileges.Enable(Privileges.TakeOwnership);
        var failed = new List<(string, int)>();
        int changed = 0, step = 0;
        const AceFlags inh = AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit;
        foreach (var n in folders)
        {
            if (ct.IsCancellationRequested) return new GrantOutcome(changed, failed, true);
            progress(++step, folders.Count, n.FullPath);
            var sd = r.SdOf(n)!;
            bool removed = false;
            var keep = new List<AceInfo>();
            foreach (var a in sd.ExplicitDaclAces)
            {
                // exactly the one entry Explorer adds; everything else stays, in order
                if (!removed && !a.IsDeny && !a.IsAudit && string.Equals(a.Sid, sid, StringComparison.OrdinalIgnoreCase)
                    && (a.Flags & inh) == (AceFlags.ObjectInherit | AceFlags.ContainerInherit) && a.NormalizedMask == 0x1F01FF)
                { removed = true; continue; }
                keep.Add(a);
            }
            if (!removed) continue;
            uint err = OrphanCleanup.SetDacl(n.FullPath, keep, sd.DaclRevision, sd.DaclProtected && keep.Count > 0);
            if (err == 0) changed++; else failed.Add((n.FullPath, (int)err));
        }
        return new GrantOutcome(changed, failed, false);
    }
}
