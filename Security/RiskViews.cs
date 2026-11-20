using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using Microsoft.Win32;

namespace AclLegibility.Security;

/// <summary>A place in a Windows-managed area where someone who is not SYSTEM, TrustedInstaller or Administrators can change things.</summary>
public sealed class WritableSpot
{
    public required ScanNode Node { get; init; }
    public required string Sid { get; init; }
    public uint Mask { get; init; }
    public bool InheritOnly { get; init; }
    /// <summary>Objects below that inherit this same grant.</summary>
    public int Below { get; set; }
    public Finding? Finding { get; init; }
    public bool Explained => Finding is { KbId: not null } f && f.Origin is Origin.Stock or Origin.Differs or Origin.Trace or Origin.PerAccount;
    /// <summary>How well the grant is explained: 2 = a path entry compared the exact ACL (rights included); 1 = a pattern
    /// knows these principals in this area but does not compare rights; 0 = unexplained.</summary>
    public int Level => !Explained ? 0 : Finding!.KbId!.StartsWith("paths/", StringComparison.Ordinal) ? 2 : 1;
}

/// <summary>A service or scheduled task that runs as SYSTEM, LOCAL SERVICE or NETWORK SERVICE.</summary>
public sealed class PrivilegedRunner
{
    public required string Kind { get; init; }       // "Service" or "Task"
    public required string Name { get; init; }
    public required string RunsAsSid { get; init; }
    public string? Command { get; init; }
    public string? Binary { get; init; }
    public bool OutsideWindows { get; init; }
    public bool UnquotedWithSpaces { get; init; }
    /// <summary>Non-admin principals that can change the binary or plant files next to it: "file: Users M", "folder: …".</summary>
    public List<string> WritableBy { get; } = new();
    public bool BinaryNotInScan { get; set; }
}

public sealed class RiskReport
{
    public List<WritableSpot> Writable { get; } = new();
    public List<PrivilegedRunner> Runners { get; } = new();
    public List<(string Task, string Sid)> DeadTasks { get; } = new();
    public List<string> Notes { get; } = new();
    public int TasksRead { get; set; }
    public int ServicesRead { get; set; }
}

/// <summary>
/// The two risk views. Writable: explicit grants in Windows-managed areas that let a non-admin principal write, create, delete,
/// change permissions or take ownership — the precondition for most local privilege escalations (planted DLLs, swapped
/// binaries, edited task files). Runners: services and tasks running as SYSTEM, LOCAL SERVICE or NETWORK SERVICE, with
/// whether a non-admin can replace what they run. Read-only; nothing here changes anything.
/// </summary>
public static class RiskViews
{
    /// <summary>Principals that are not the system's own: everyone, signed-in users, guests, and any local or domain account.</summary>
    public static bool IsNonAdmin(string sid)
    {
        switch (sid)
        {
            case "S-1-1-0": case "S-1-5-11": case "S-1-5-32-545": case "S-1-5-4": case "S-1-5-32-546":
            case "S-1-5-7": case "S-1-5-2": case "S-1-5-14": case "S-1-2-0": case "S-1-2-1":
                return true;
        }
        if (SidText.SplitAccountSid(sid) is { } split) return split.Rid >= 1000 || split.Rid is 501 or 513 or 514;
        return false;
    }

    public static RiskReport Build(ScanResult r, Classifier cls)
    {
        var rep = new RiskReport();
        Writable(r, rep);
        if (r.IsLive)
        {
            try { Services(r, rep); } catch (Exception ex) { rep.Notes.Add("Services could not be read: " + ex.Message); }
            try { Tasks(r, cls, rep); } catch (Exception ex) { rep.Notes.Add("Scheduled tasks could not be read: " + ex.Message); }
        }
        else rep.Notes.Add("Services and scheduled tasks can only be read on the machine that was scanned; the writable view below comes from the snapshot.");
        rep.Runners.Sort((a, b) =>
        {
            int c = (b.WritableBy.Count > 0).CompareTo(a.WritableBy.Count > 0);
            if (c != 0) return c;
            c = b.OutsideWindows.CompareTo(a.OutsideWindows);
            return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });
        return rep;
    }

    // ---- writable by non-admins -------------------------------------------------------------------

    private static IEnumerable<ScanNode> AreaRoots(ScanResult r)
    {
        var seen = new HashSet<ScanNode>();
        foreach (var key in new[] { "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData" })
            if (r.Os.Paths.TryGetValue(key, out var path) && r.FindByPath(path) is { } n && seen.Add(n)) yield return n;
    }

    private static void Writable(ScanResult r, RiskReport rep)
    {
        var spots = new Dictionary<(ScanNode, string), WritableSpot>();
        // The system drive root itself (its own explicit entries only; the areas below are walked separately).
        if (r.Os.Paths.TryGetValue("SystemDrive", out var sdrive) && r.FindByPath(sdrive + "\\") is { } root)
            AddSpots(r, root, spots);
        foreach (var top in AreaRoots(r))
        {
            var stack = new Stack<ScanNode>();
            stack.Push(top);
            while (stack.Count > 0)
            {
                var n = stack.Pop();
                AddSpots(r, n, spots);
                if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
            }
        }
        // Objects below that inherit the grant: attribute each to the nearest ancestor where it is explicit.
        foreach (var top in AreaRoots(r))
        {
            var stack = new Stack<ScanNode>();
            stack.Push(top);
            while (stack.Count > 0)
            {
                var n = stack.Pop();
                if (r.SdOf(n)?.Dacl is { } dacl)
                    foreach (var a in dacl)
                    {
                        if (!a.IsInherited || !a.IsAllow || a.IsInheritOnly || (a.NormalizedMask & Classifier.ControlRights) == 0 || !IsNonAdmin(a.Sid)) continue;
                        for (var up = n.Parent; up != null; up = up.Parent)
                            if (spots.TryGetValue((up, a.Sid), out var spot)) { spot.Below++; break; }
                    }
                if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
            }
        }
        rep.Writable.AddRange(spots.Values
            .OrderBy(s => s.Level)
            .ThenByDescending(s => s.Below)
            .ThenBy(s => s.Node.FullPath, StringComparer.OrdinalIgnoreCase));
    }

    private static void AddSpots(ScanResult r, ScanNode n, Dictionary<(ScanNode, string), WritableSpot> spots)
    {
        var sd = r.SdOf(n);
        if (sd?.Dacl == null) return;
        foreach (var a in sd.Dacl)
        {
            if (a.IsInherited || !a.IsAllow || !IsNonAdmin(a.Sid)) continue;
            var bits = a.NormalizedMask & Classifier.ControlRights;
            if (bits == 0) continue;
            // An explicit deny for the same account on the same rights cancels it.
            if (sd.Dacl.Any(d => d.IsDeny && !d.IsInheritOnly && d.Sid == a.Sid && (d.NormalizedMask & bits) == bits)) continue;
            if (spots.TryGetValue((n, a.Sid), out var existing)) continue;
            spots[(n, a.Sid)] = new WritableSpot
            {
                Node = n, Sid = a.Sid, Mask = a.NormalizedMask, InheritOnly = a.IsInheritOnly,
                Finding = AclFindingFor(n, a.Sid, r),
            };
        }
    }

    /// <summary>The permissions finding that stands for this object's explicit entries: its own, or the folder's it was folded into.</summary>
    private static Finding? AclFindingFor(ScanNode n, string sid, ScanResult r)
    {
        for (var x = n; x != null; x = x.Parent)
        {
            var f = x.Findings?.FirstOrDefault(f => f.Category == FindingCategory.Acl);
            if (f != null) return x == n || r.SdOf(x)?.ExplicitDaclAces.Any(a => a.Sid == sid) == true ? f : null;
            if (r.SdOf(x)?.ExplicitDaclAces.Any(a => a.Sid == sid) != true) return null;
        }
        return null;
    }

    /// <summary>What a non-admin can do to a file and its folder, from the scan's descriptors (inherited entries included).</summary>
    public static void CheckBinary(ScanResult r, PrivilegedRunner pr, string path)
    {
        var node = r.FindByPath(path);
        if (node == null) { pr.BinaryNotInScan = true; return; }
        void Check(ScanNode x, string label, bool isFolder)
        {
            if (r.SdOf(x)?.Dacl is not { } dacl) return;
            foreach (var a in dacl)
            {
                if (!a.IsAllow || a.IsInheritOnly || !IsNonAdmin(a.Sid)) continue;
                // On the folder, only rights that let someone put a file there or replace the folder count.
                uint relevant = isFolder ? (0x2u | 0x10000 | 0x40000 | 0x80000) : Classifier.ControlRights;
                var bits = a.NormalizedMask & relevant;
                if (bits == 0) continue;
                if (dacl.Any(d => d.IsDeny && !d.IsInheritOnly && d.Sid == a.Sid && (d.NormalizedMask & bits) == bits)) continue;
                pr.WritableBy.Add($"{label}: {r.NameOf(a.Sid).Display} {Rights.Short(bits)}");
            }
        }
        Check(node, "file", false);
        if (node.Parent != null) Check(node.Parent, "its folder", true);
    }

    // ---- services --------------------------------------------------------------------------------

    private static void Services(ScanResult r, RiskReport rep)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root == null) return;
        r.Os.Paths.TryGetValue("SystemRoot", out var sysRoot);
        foreach (var name in root.GetSubKeyNames())
        {
            using var k = root.OpenSubKey(name);
            if (k?.GetValue("Type") is not int type) continue;
            if ((type & 0x30) == 0 || (type & 0x40) != 0) continue;           // own/shared process; not per-user templates or drivers
            if (k.GetValue("ImagePath") is not string image || image.Length == 0) continue;
            rep.ServicesRead++;
            var obj = (k.GetValue("ObjectName") as string ?? "LocalSystem").Trim();
            var sid = obj.ToUpperInvariant() switch
            {
                "LOCALSYSTEM" or "NT AUTHORITY\\SYSTEM" or ".\\LOCALSYSTEM" => "S-1-5-18",
                "NT AUTHORITY\\LOCALSERVICE" or "NT AUTHORITY\\LOCAL SERVICE" => "S-1-5-19",
                "NT AUTHORITY\\NETWORKSERVICE" or "NT AUTHORITY\\NETWORK SERVICE" => "S-1-5-20",
                _ => null,
            };
            if (sid == null) continue;
            var (binary, unquoted) = ParseCommand(image, sysRoot);
            if (binary != null && FileName(binary).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            {
                using var par = k.OpenSubKey("Parameters");
                if ((par?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) ?? k.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)) is string dll)
                    binary = ParseCommand(dll, sysRoot).Binary ?? binary;
            }
            bool outside = binary != null && sysRoot != null && !binary.StartsWith(sysRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
            var pr = new PrivilegedRunner
            {
                Kind = "Service", Name = name + (k.GetValue("DisplayName") is string dn && !dn.StartsWith('@') && dn != name ? $" ({dn})" : ""),
                RunsAsSid = sid, Command = image, Binary = binary, OutsideWindows = outside, UnquotedWithSpaces = unquoted,
            };
            if (binary != null) CheckBinary(r, pr, binary);
            if (outside || pr.WritableBy.Count > 0 || unquoted) rep.Runners.Add(pr);
        }
    }

    // ---- scheduled tasks -----------------------------------------------------------------------

    private static void Tasks(ScanResult r, Classifier cls, RiskReport rep)
    {
        if (!r.Os.Paths.TryGetValue("SystemRoot", out var sysRoot)) return;
        var storePath = sysRoot.TrimEnd('\\') + "\\System32\\Tasks";
        if (r.FindByPath(storePath) is not { } store) return;
        var stack = new Stack<(ScanNode Node, string Rel)>();
        stack.Push((store, ""));
        while (stack.Count > 0)
        {
            var (node, rel) = stack.Pop();
            foreach (var c in node.Children ?? Enumerable.Empty<ScanNode>())
            {
                var crel = rel + "\\" + c.Name;
                if (c.IsDirectory) { stack.Push((c, crel)); continue; }
                if (KnownFacts.ReadTask(c.FullPath) is not { } t) continue;
                rep.TasksRead++;
                var sid = KnownFacts.RunsAsSid(t);
                if (sid != null && cls.OrphanStateOf(sid) == OrphanState.Proven) rep.DeadTasks.Add((crel, sid));
                if (sid is not ("S-1-5-18" or "S-1-5-19" or "S-1-5-20")) continue;
                bool microsoft = crel.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase);
                foreach (var cmd in t.Commands.Where(x => !x.StartsWith("COM handler", StringComparison.Ordinal)))
                {
                    var (binary, unquoted) = ParseCommand(cmd, sysRoot);
                    bool outside = binary != null && !binary.StartsWith(sysRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
                    var pr = new PrivilegedRunner
                    {
                        Kind = "Task", Name = crel, RunsAsSid = sid, Command = cmd, Binary = binary,
                        OutsideWindows = outside || !microsoft, UnquotedWithSpaces = unquoted,
                    };
                    if (binary != null) CheckBinary(r, pr, binary);
                    if (!microsoft || outside || pr.WritableBy.Count > 0) rep.Runners.Add(pr);
                }
            }
        }
    }

    /// <summary>The executable a command line starts: quoted path, or an unquoted path up to ".exe"/".dll"/".sys";
    /// \SystemRoot\, \??\ and %variables% expanded; a bare name is looked up in System32.</summary>
    public static (string? Binary, bool UnquotedWithSpaces) ParseCommand(string command, string? sysRoot)
    {
        var s = Environment.ExpandEnvironmentVariables(command.Trim());
        string? path;
        bool unquoted = false;
        if (s.StartsWith('"'))
        {
            int end = s.IndexOf('"', 1);
            path = end > 1 ? s[1..end] : s.Trim('"');
        }
        else
        {
            int best = -1;
            foreach (var ext in new[] { ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1" })
            {
                int i = s.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
                if (i >= 0 && (best < 0 || i < best)) best = i + ext.Length;
            }
            path = best > 0 ? s[..best] : s.Split(' ')[0];
            unquoted = path.Contains(' ');
        }
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (sysRoot != null && path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = sysRoot.TrimEnd('\\') + path[11..];
        if (sysRoot != null && path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) path = sysRoot.TrimEnd('\\') + "\\" + path;
        if (sysRoot != null && !IsRooted(path) && !path.Contains('\\')) path = sysRoot.TrimEnd('\\') + "\\System32\\" + path;
        if (!IsRooted(path)) return (null, unquoted);
        return (path, unquoted);
    }

    /// <summary>A Windows absolute path: drive letter and backslash, or a UNC path.</summary>
    private static bool IsRooted(string p) =>
        p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\' || p.StartsWith(@"\\", StringComparison.Ordinal);

    private static string FileName(string p) => p[(p.LastIndexOf('\\') + 1)..];
}
