using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using AclLegibility.Model;
using AclLegibility.Native;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Security;

/// <summary>What "Reset to inherit" would do below one folder: which objects change, which are skipped and why.</summary>
public sealed class ResetPlan
{
    public required ScanNode Target { get; init; }
    /// <summary>Folder the backup paths are relative to; the restore command runs icacls on it.</summary>
    public required string RestoreBase { get; init; }
    public List<ScanNode> Change { get; } = new();
    public List<(ScanNode Node, string Reason)> Skipped { get; } = new();
    public int SkippedObjects { get; set; }      // including everything below skipped folders
    public int AlreadyInheriting { get; set; }
    /// <summary>Entries everything will inherit (from the target's parent, or the root itself).</summary>
    public List<AceInfo> Inherits { get; } = new();
    /// <summary>Places you said hold another Windows installation or image: left alone with everything below them.</summary>
    public List<string> LeftAlone { get; } = new();
}

public sealed record ResetOutcome(int Changed, List<(string Path, int Error)> Failed, bool Cancelled);

/// <summary>
/// Removes explicit entries and turns inheritance on below a folder of a non-system drive — one of
/// the permission actions. Never touches system folders, links, or objects whose explicit entries serve a
/// VM, service, app pool or app package. A verified icacls backup is written before the first change.
/// </summary>
public static class ResetToInherit
{
    private static readonly string[] SystemFolderNames = { "$RECYCLE.BIN", "System Volume Information" };

    /// <summary>Null when allowed, otherwise the reason it is not.</summary>
    public static string? WhyNot(ScanResult r, ScanNode n)
    {
        if (!r.IsLive) return "Only on a live scan of this machine, not on a snapshot.";
        if (!n.IsDirectory) return "Only for folders.";
        if (r.Cancelled) return "The scan was cancelled, so the folder may be incomplete. Scan again first.";
        var path = n.FullPath;
        var volume = VolumeOf(path);
        var systemDrive = (r.Os.Paths.TryGetValue("SystemDrive", out var sd) ? sd : "C:").TrimEnd('\\') + "\\";
        if (string.Equals(volume, systemDrive, StringComparison.OrdinalIgnoreCase)) return "Not on the Windows drive.";
        if (n.Extra?.Reparse != null) return "This folder is a link; links are left as they are.";
        foreach (var part in path.Substring(volume.Length).Split('\\', StringSplitOptions.RemoveEmptyEntries))
            if (SystemFolderNames.Contains(part, StringComparer.OrdinalIgnoreCase)) return "Inside a system folder.";
        return null;
    }

    /// <summary>"D:\\" for "D:\\Data\\x" (drive letters parsed directly, independent of the host OS).</summary>
    public static string VolumeOf(string path) =>
        path.Length >= 2 && path[1] == ':' ? char.ToUpperInvariant(path[0]) + ":\\" : Path.GetPathRoot(path) ?? "";

    /// <summary>Why an object's explicit entries must stay, or null.</summary>
    private static string? NeedsExplicit(ScanResult r, SdInfo sd)
    {
        foreach (var a in sd.ExplicitDaclAces)
        {
            string? what =
                a.Sid.StartsWith("S-1-5-83-", StringComparison.Ordinal) ? "a virtual machine" :
                a.Sid.StartsWith("S-1-5-80-", StringComparison.Ordinal) ? "a service" :
                a.Sid.StartsWith("S-1-5-82-", StringComparison.Ordinal) ? "an IIS app pool" :
                a.Sid.StartsWith("S-1-15-2-", StringComparison.Ordinal) ? "an app package" : null;
            if (what != null)
            {
                var p = r.NameOf(a.Sid);
                return $"explicit entry for {what} ({(p.Resolved ? p.Display : a.Sid)})";
            }
        }
        return null;
    }

    /// <param name="leaveAlone">Places the user said hold another Windows installation or image: left alone with their subtree.</param>
    public static ResetPlan Plan(ScanResult r, ScanNode target, IReadOnlyCollection<string>? leaveAlone = null)
    {
        bool targetIsRoot = target.IsRoot && (target.Flags & NodeFlags.IsVolumeRoot) != 0;
        var restoreBase = targetIsRoot ? target.FullPath : target.Parent?.FullPath ?? Path.GetDirectoryName(target.FullPath.TrimEnd('\\')) ?? target.FullPath;
        var plan = new ResetPlan { Target = target, RestoreBase = restoreBase };

        var source = targetIsRoot ? target : target.Parent;
        var sourceSd = source != null ? r.SdOf(source) : null;
        if (sourceSd?.Dacl != null)
            plan.Inherits.AddRange(sourceSd.Dacl.Where(a => (a.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) != 0));

        var stack = new Stack<ScanNode>();
        stack.Push(target);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            bool isTargetRoot = n == target && targetIsRoot;
            if (ForeignWindows.HolderOf(n.FullPath, leaveAlone) is { } holder)
            {
                if (!plan.LeftAlone.Contains(holder, StringComparer.OrdinalIgnoreCase)) plan.LeftAlone.Add(holder);
                Skip(plan, n, "another Windows installation or image (your answer) — left alone", true);
                continue;
            }
            if (!isTargetRoot)
            {
                if (n.IsDirectory && SystemFolderNames.Contains(n.Name, StringComparer.OrdinalIgnoreCase))
                { Skip(plan, n, "system folder", true); continue; }
                if (n.Extra?.Reparse != null) { Skip(plan, n, "link — left as it is", false); continue; }
                var sd = r.SdOf(n);
                if (sd == null) { Skip(plan, n, "permissions could not be read", false); }
                else if (NeedsExplicit(r, sd) is { } why) { Skip(plan, n, why, true); continue; }
                else if (sd.DaclProtected || sd.HasExplicitDaclAce) plan.Change.Add(n);
                else plan.AlreadyInheriting++;
            }
            if (n.Children != null)
                for (int i = n.Children.Count - 1; i >= 0; i--) stack.Push(n.Children[i]);
        }
        return plan;
    }

    private static void Skip(ResetPlan plan, ScanNode n, string reason, bool withSubtree)
    {
        plan.Skipped.Add((n, reason));
        plan.SkippedObjects += withSubtree ? Count(n) : 1;
    }

    private static int Count(ScanNode n)
    {
        int c = 0;
        var s = new Stack<ScanNode>();
        s.Push(n);
        while (s.Count > 0) { var x = s.Pop(); c++; if (x.Children != null) foreach (var ch in x.Children) s.Push(ch); }
        return c;
    }

    /// <summary>Writes the current DACLs of every object that will change (icacls format) and verifies the file.</summary>
    public static void WriteBackup(ScanResult r, ResetPlan plan, string file) => IcaclsBackup.Write(r, plan.Change, plan.RestoreBase, file);

    public static string RestoreCommand(ResetPlan plan, string file) => IcaclsBackup.RestoreCommand(plan.RestoreBase, file);

    /// <summary>Applies the plan, parents before children so each object inherits from its final parent.</summary>
    public static ResetOutcome Run(ResetPlan plan, Action<int, int, string> progress, CancellationToken ct)
    {
        Privileges.Enable(Privileges.Restore);
        var failed = new List<(string, int)>();
        int changed = 0;
        IntPtr acl = Marshal.AllocHGlobal(8);
        try
        {
            if (!InitializeAcl(acl, 8, ACL_REVISION)) throw new InvalidOperationException("Could not build an empty ACL.");
            for (int i = 0; i < plan.Change.Count; i++)
            {
                if (ct.IsCancellationRequested) return new ResetOutcome(changed, failed, true);
                var path = plan.Change[i].FullPath;
                if (i % 25 == 0) progress(i, plan.Change.Count, path);
                var name = FileProbe.Long(path);   // always \\?\: a plain path loses a trailing dot or space
                uint err = SetNamedSecurityInfoW(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, acl, IntPtr.Zero);
                if (err == 0) changed++;
                else failed.Add((path, (int)err));
            }
        }
        finally { Marshal.FreeHGlobal(acl); }
        progress(plan.Change.Count, plan.Change.Count, "");
        return new ResetOutcome(changed, failed, false);
    }
}
