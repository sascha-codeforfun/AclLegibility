using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Native;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Security;

/// <summary>A profile of a proven orphan: Windows' profile list still names it, the account is gone.</summary>
public sealed class ProfilePlan
{
    public required string Sid { get; init; }
    public required string Path { get; init; }
    public ScanNode? Node { get; init; }
    public long Bytes { get; set; }
    public int Objects { get; set; }
    /// <summary>Personal files outside AppData by category: these trigger the offer to save them as a ZIP first.</summary>
    public Dictionary<string, (int Count, long Bytes)> Personal { get; } = new();
    public List<ScanNode> PersonalFiles { get; } = new();
    /// <summary>Files of the same types inside AppData — app data, listed but not counted as personal.</summary>
    public int AppDataCount { get; set; }
    public long AppDataBytes { get; set; }
    public bool HasPersonal => PersonalFiles.Count > 0;
}

/// <summary>What orphan cleanup would do: owners to replace, entries to remove, leftover folders to delete,
/// what is only looked at (inside %SystemRoot%) and what is left and why.</summary>
public sealed class OrphanPlan
{
    public required IReadOnlyCollection<string> Sids { get; init; }
    /// <summary>Objects whose owner is one of the SIDs → owner becomes Administrators.</summary>
    public List<ScanNode> Owners { get; } = new();
    /// <summary>Objects with explicit entries for one of the SIDs → those entries are removed (parents first).</summary>
    public List<ScanNode> Entries { get; } = new();
    /// <summary>Folders named after one of the SIDs (a deleted account's Group Policy folder, recycle bin, …) → deleted.</summary>
    public List<(ScanNode Folder, long Bytes, int Objects)> Leftovers { get; } = new();
    /// <summary>Profiles of these SIDs (folder and profile-list entry) → deleted through Windows' DeleteProfileW.</summary>
    public List<ProfilePlan> Profiles { get; } = new();
    /// <summary>Inside %SystemRoot%: found, not touched — to be explained before anything is decided.</summary>
    public List<(ScanNode Node, string What)> Inside { get; } = new();
    /// <summary>Inside %SystemRoot%, but a knowledge entry explains why these files are leftovers and safe to delete
    /// (pattern with "removable"). Offered one by one, never ticked by default.</summary>
    public List<(ScanNode Node, string Why, string KbId)> Removable { get; } = new();
    /// <summary>The removable files the user ticked in the preview.</summary>
    public List<ScanNode> RemoveChosen { get; } = new();
    public List<(ScanNode Node, string Reason)> Skipped { get; } = new();
    public Dictionary<string, (int Owned, int WithEntries, int Folders, int Inside)> PerSid { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Places you said hold another Windows installation or image: everything there is left alone (objects counted).</summary>
    public Dictionary<string, int> LeftAlone { get; } = new(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<IGrouping<string, ScanNode>> EntriesByDrive =>
        Entries.GroupBy(n => ResetToInherit.VolumeOf(n.FullPath), StringComparer.OrdinalIgnoreCase);
    public long LeftoverBytes => Leftovers.Sum(l => l.Bytes);
    public bool HasWork => Owners.Count + Entries.Count + Leftovers.Count + Profiles.Count + Removable.Count > 0;
    /// <summary>Every object the plan would change or delete (for the question about other Windows installations).</summary>
    public IEnumerable<ScanNode> Touched =>
        Owners.Concat(Entries).Concat(Leftovers.Select(l => l.Folder)).Concat(Profiles.Where(x => x.Node != null).Select(x => x.Node!))
              .Concat(Removable.Select(x => x.Node));
}

public sealed record CleanupOutcome(int OwnersChanged, int EntriesChanged, int FoldersDeleted, long BytesFreed,
    List<(string Path, int Error)> Failed, bool Cancelled, List<ScanNode> DeletedFolders, int ProfilesDeleted = 0, int FilesDeleted = 0);

/// <summary>
/// Removes proven orphaned SIDs completely, outside %SystemRoot%: replaces orphaned owners with Administrators,
/// removes explicit entries for those SIDs (every other entry stays) and deletes leftover folders named after
/// them. Inside %SystemRoot% (servicing territory) it only looks and lists what it found. Never touches
/// unverifiable SIDs, links, drive roots or auditing entries. Entries are backed up in icacls format (one file
/// per drive) before the first change; owners cannot be restored — the account is gone — and deleted folders
/// cannot be restored either.
/// </summary>
public static class OrphanCleanup
{
    public const string Administrators = "S-1-5-32-544";

    public static string? WhyNot(ScanResult r)
    {
        if (!r.IsLive) return "Only on a live scan of this machine, not on a snapshot.";
        if (r.Cancelled) return "The scan was cancelled, so it may be incomplete. Scan again first.";
        return null;
    }

    /// <param name="leaveAlone">Places the user said hold another Windows installation or image: nothing there is planned.</param>
    public static OrphanPlan Plan(ScanResult r, Classifier cls, CompiledKb kb, IEnumerable<string> sids, IReadOnlyCollection<string>? leaveAlone = null)
    {
        var set = new HashSet<string>(sids.Where(s => cls.OrphanStateOf(s) == OrphanState.Proven), StringComparer.OrdinalIgnoreCase);
        var plan = new OrphanPlan { Sids = set };
        foreach (var s in set) plan.PerSid[s] = (0, 0, 0, 0);
        if (set.Count == 0) return plan;
        r.Os.Paths.TryGetValue("SystemRoot", out var sysRoot);
        bool InSystemRoot(ScanNode n) => sysRoot != null &&
            (n.FullPath.Equals(sysRoot, StringComparison.OrdinalIgnoreCase)
             || n.FullPath.StartsWith(sysRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
        void Count(string sid, int owned = 0, int entries = 0, int folders = 0, int inside = 0)
        {
            var t = plan.PerSid[sid];
            plan.PerSid[sid] = (t.Owned + owned, t.WithEntries + entries, t.Folders + folders, t.Inside + inside);
        }

        var doomed = new HashSet<ScanNode>();
        var insideNodes = new HashSet<ScanNode>();
        bool LeftAlone(string path)
        {
            if (ForeignWindows.HolderOf(path, leaveAlone) is not { } holder) return false;
            plan.LeftAlone[holder] = plan.LeftAlone.GetValueOrDefault(holder) + 1;
            return true;
        }

        // 0. profiles of these SIDs (the profile list still names them) — the whole profile goes with Windows' own function
        foreach (var sid in set)
        {
            if (!r.Os.Profiles.TryGetValue(sid, out var path)) continue;
            if (LeftAlone(path)) continue;
            var node = r.FindByPath(path);
            var pp = new ProfilePlan { Sid = sid, Path = path, Node = node };
            if (node != null)
                foreach (var x in Subtree(node))
                {
                    doomed.Add(x); pp.Objects++;
                    if (x.IsDirectory) continue;
                    pp.Bytes += x.Size;
                    var ext = System.IO.Path.GetExtension(x.Name).ToLowerInvariant();
                    if (!PersonalTypes.TryGetValue(ext, out var cat)) continue;
                    var rel = x.FullPath.Length > path.Length ? x.FullPath[(path.Length + 1)..] : x.Name;
                    if (rel.StartsWith("AppData\\", StringComparison.OrdinalIgnoreCase)) { pp.AppDataCount++; pp.AppDataBytes += x.Size; continue; }
                    var t = pp.Personal.GetValueOrDefault(cat);
                    pp.Personal[cat] = (t.Count + 1, t.Bytes + x.Size);
                    pp.PersonalFiles.Add(x);
                }
            plan.Profiles.Add(pp);
        }

        // 1. leftover folders named after an orphaned SID — their whole subtree goes, so nothing in it needs fixing
        foreach (var n in r.AllNodes())
        {
            if (!n.IsDirectory || n.IsRoot || n.Extra?.Reparse != null || !set.Contains(n.Name)) continue;
            if (n.Ancestors().Any(doomed.Contains)) continue;
            if (LeftAlone(n.FullPath)) continue;
            if (InSystemRoot(n))
            {
                var cmd = Classifier.TaskCommand(n, r.Os);
                plan.Inside.Add((n, "folder named after the SID" + (cmd != null ? " — scheduled task folder: " + cmd : "")));
                insideNodes.Add(n);
                Count(n.Name, inside: 1);
                continue;
            }
            long bytes = 0; int objects = 0;
            foreach (var x in Subtree(n)) { doomed.Add(x); objects++; if (!x.IsDirectory) bytes += x.Size; }
            plan.Leftovers.Add((n, bytes, objects));
            Count(n.Name, folders: 1);
        }

        // 2. owners and entries
        foreach (var n in r.AllNodes())
        {
            if (doomed.Contains(n)) continue;
            var sd = r.SdOf(n);
            if (sd == null) continue;
            bool owned = sd.Owner != null && set.Contains(sd.Owner);
            var orphanSids = sd.ExplicitDaclAces.Where(a => set.Contains(a.Sid)).Select(a => a.Sid)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (!owned && orphanSids.Count == 0) continue;
            if (LeftAlone(n.FullPath)) continue;

            if (InSystemRoot(n))
            {
                if (insideNodes.Contains(n)) continue;   // already listed as a SID-named folder
                if (!n.IsDirectory && n.Extra?.Reparse == null && cls.RemovableWhy(n) is { } why)
                {
                    plan.Removable.Add((n, why.Explain, why.KbId));
                    if (owned) Count(sd.Owner!, inside: 1);
                    foreach (var sid in orphanSids.Where(x => !owned || !x.Equals(sd.Owner, StringComparison.OrdinalIgnoreCase))) Count(sid, inside: 1);
                    continue;
                }
                var what = string.Join(", ", new[] { owned ? "owner" : null, orphanSids.Count > 0 ? "explicit entries" : null }.Where(w => w != null))
                           + (Classifier.TaskCommand(n, r.Os) is { } cmd ? " — scheduled task: " + cmd : "");
                plan.Inside.Add((n, what));
                if (owned) Count(sd.Owner!, inside: 1);
                foreach (var sid in orphanSids.Where(x => !owned || !x.Equals(sd.Owner, StringComparison.OrdinalIgnoreCase))) Count(sid, inside: 1);
                continue;
            }
            if (n.Extra?.Reparse != null) { plan.Skipped.Add((n, "link — left as it is")); continue; }

            if (owned) { plan.Owners.Add(n); Count(sd.Owner!, owned: 1); }
            if (orphanSids.Count == 0) continue;
            if (n.IsRoot) plan.Skipped.Add((n, "drive root — change its entries by hand"));
            else plan.Entries.Add(n);
            foreach (var sid in orphanSids) Count(sid, entries: 1);
        }
        return plan;
    }

    /// <summary>File types that count as personal (outside AppData) and trigger the offer to back them up first.</summary>
    public static readonly Dictionary<string, string> PersonalTypes = Build(new()
    {
        ["Documents"] = ".pdf .docx .doc .xlsx .xls .pptx .odt .ods .txt .rtf .md",
        ["Pictures"] = ".jpg .jpeg .png .gif .heic .raw .cr2 .nef .webp",
        ["Videos"] = ".mp4 .mov .mkv .avi",
        ["Audio"] = ".mp3 .flac .wav .m4a",
        ["Archives"] = ".zip .7z .rar",
        ["Secrets"] = ".pfx .p12 .pem .key .kdbx",
    });

    private static Dictionary<string, string> Build(Dictionary<string, string> cats)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (cat, exts) in cats) foreach (var e in exts.Split(' ')) d[e] = cat;
        return d;
    }

    internal static IEnumerable<ScanNode> Subtree(ScanNode top)
    {
        var stack = new Stack<ScanNode>();
        stack.Push(top);
        while (stack.Count > 0)
        {
            var x = stack.Pop();
            yield return x;
            if (x.Children != null) foreach (var c in x.Children) stack.Push(c);
        }
    }

    /// <summary>Backup file per drive: the chosen name as is for one drive, "-D" etc. before the extension for several.</summary>
    public static List<(string Drive, string File, IReadOnlyList<ScanNode> Nodes)> BackupFiles(OrphanPlan plan, string chosen)
    {
        var groups = plan.EntriesByDrive.ToList();
        var result = new List<(string, string, IReadOnlyList<ScanNode>)>();
        foreach (var g in groups)
        {
            var file = groups.Count == 1 ? chosen
                : Path.Combine(Path.GetDirectoryName(chosen) ?? "", Path.GetFileNameWithoutExtension(chosen) + "-" + g.Key.TrimEnd('\\', ':') + Path.GetExtension(chosen));
            result.Add((g.Key, file, g.ToList()));
        }
        return result;
    }

    /// <summary>The profile, leftover folder or ticked file that a path lies in (or is), when the clean-up would delete it —
    /// a ZIP or backup saved there would go with it. Null when the path is safe.</summary>
    public static string? DoomedHolder(OrphanPlan plan, IEnumerable<ProfilePlan> profiles, string path)
    {
        static bool Inside(string p, string doomed)
        {
            var d = doomed.TrimEnd('\\');
            return p.Equals(d, StringComparison.OrdinalIgnoreCase) || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
        }
        var doomed = profiles.Select(x => x.Path)
            .Concat(plan.Leftovers.Select(l => l.Folder.FullPath))
            .Concat(plan.RemoveChosen.Select(f => f.FullPath));
        return doomed.FirstOrDefault(d => Inside(path, d));
    }

    public static void WriteBackups(ScanResult r, OrphanPlan plan, string chosen)
    {
        foreach (var (drive, file, nodes) in BackupFiles(plan, chosen))
            IcaclsBackup.Write(r, nodes, drive, file);
    }

    public static CleanupOutcome Run(ScanResult r, OrphanPlan plan, IReadOnlyCollection<ProfilePlan> profiles,
        Action<int, int, string> progress, CancellationToken ct)
    {
        Privileges.Enable(Privileges.Restore);
        Privileges.Enable(Privileges.TakeOwnership);
        var failed = new List<(string, int)>();
        var deleted = new List<ScanNode>();
        int entries = 0, owners = 0, folders = 0, step = 0;
        long freed = 0;
        int total = plan.Entries.Count + plan.Owners.Count + plan.Leftovers.Sum(l => l.Objects) + plan.RemoveChosen.Count;
        int profilesDeleted = 0, files = 0;
        CleanupOutcome Stop() => new(owners, entries, folders, freed, failed, true, deleted, profilesDeleted, files);

        // profiles: Windows' own function removes folder and profile-list entry together
        foreach (var pp in profiles)
        {
            if (ct.IsCancellationRequested) return Stop();
            progress(step, total, pp.Path);
            if (DeleteProfileW(pp.Sid, null, null)) { profilesDeleted++; freed += pp.Bytes; if (pp.Node != null) deleted.Add(pp.Node); }
            else failed.Add((pp.Path, Marshal.GetLastWin32Error()));
        }

        // 0. leftover folders — children before parents; a folder whose contents could not all go stays
        foreach (var (folder, bytes, _) in plan.Leftovers)
        {
            bool ok = true;
            foreach (var x in Subtree(folder).Reverse())
            {
                if (ct.IsCancellationRequested) return Stop();
                if (step++ % 25 == 0) progress(step, total, x.FullPath);
                uint err = Delete(x.FullPath);
                if (err != 0 && err != 2 && err != 3) { ok = false; failed.Add((x.FullPath, (int)err)); }
            }
            if (ok) { folders++; freed += bytes; deleted.Add(folder); }
        }

        // 0b. explained leftovers inside %SystemRoot% that the user ticked — single files only
        foreach (var f in plan.RemoveChosen)
        {
            if (ct.IsCancellationRequested) return Stop();
            progress(step++, total, f.FullPath);
            uint err = Delete(f.FullPath);
            if (err == 0 || err == 2) { files++; freed += f.Size; deleted.Add(f); }
            else failed.Add((f.FullPath, (int)err));
        }

        // 1. entries — parents before children (scan order), keeping every other explicit entry and the protection flag
        foreach (var n in plan.Entries)
        {
            if (ct.IsCancellationRequested) return Stop();
            if (step++ % 25 == 0) progress(step, total, n.FullPath);
            var sd = r.SdOf(n)!;
            var keep = sd.ExplicitDaclAces.Where(a => !plan.Sids.Contains(a.Sid)).ToList();
            // A protected DACL whose only entries were the orphan's would end up empty (nobody has access):
            // turn inheritance on instead, so the object gets its parent's entries.
            bool keepProtected = sd.DaclProtected && keep.Count > 0;
            uint err = SetDacl(n.FullPath, keep, sd.DaclRevision, keepProtected);
            if (err == 0) entries++; else failed.Add((n.FullPath, (int)err));
        }

        // 2. owners → Administrators
        var admins = SidText.ToBinary(Administrators)!;
        var pAdmins = Marshal.AllocHGlobal(admins.Length);
        try
        {
            Marshal.Copy(admins, 0, pAdmins, admins.Length);
            foreach (var n in plan.Owners)
            {
                if (ct.IsCancellationRequested) return Stop();
                if (step++ % 50 == 0) progress(step, total, n.FullPath);
                uint err = SetNamedSecurityInfoW(Name(n.FullPath), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                    pAdmins, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (err == 0) owners++; else failed.Add((n.FullPath, (int)err));
            }
        }
        finally { Marshal.FreeHGlobal(pAdmins); }
        progress(total, total, "");
        return new CleanupOutcome(owners, entries, folders, freed, failed, false, deleted, profilesDeleted, files);
    }

    /// <summary>Deletes a folder and everything in it as it is on disk now (not as scanned), children before parents, with
    /// backup semantics. Links inside are deleted as links, never followed. Returns false when anything stayed; what
    /// could not be deleted goes to <paramref name="failed"/> and its folders stay.</summary>
    internal static bool DeleteTree(string path, List<(string Path, int Error)> failed, ref long bytes, CancellationToken ct)
    {
        var probe = new FileProbe(false);
        var entries = new List<DirEntry>();
        int err = probe.ListDirectory(path, entries);
        if (err == 2 || err == 3) return true;            // already gone
        if (err != 0) { failed.Add((path, err)); return false; }
        bool ok = true;
        var prefix = path.TrimEnd('\\') + "\\";
        foreach (var e in entries.ToList())
        {
            if (ct.IsCancellationRequested) return false;
            var child = prefix + e.Name;
            bool isDir = (e.Attributes & (uint)FileAttributes.Directory) != 0;
            bool isLink = (e.Attributes & (uint)FileAttributes.ReparsePoint) != 0;
            if (isDir && !isLink) { if (!DeleteTree(child, failed, ref bytes, ct)) ok = false; continue; }
            uint de = Delete(child);
            if (de == 0 || de == 2 || de == 3) { if (!isDir) bytes += e.Size; }
            else { ok = false; failed.Add((child, (int)de)); }
        }
        if (!ok) return false;
        uint d = Delete(path);
        if (d == 0 || d == 2 || d == 3) return true;
        failed.Add((path, (int)d));
        return false;
    }

    /// <summary>Deletes one file or empty folder with backup semantics, so the restore privilege opens it whatever its
    /// entries say (a deleted account's folder often grants only that account). Read-only is ignored.</summary>
    internal static uint Delete(string path)
    {
        using var h = CreateFileW(FileProbe.Long(path), DELETE | FILE_WRITE_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h.IsInvalid) return (uint)Marshal.GetLastWin32Error();
        uint flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (SetFileInformationByHandle(h, FileDispositionInfoEx, ref flags, sizeof(uint))) return 0;
        uint err = (uint)Marshal.GetLastWin32Error();
        // Only an older file system or build that lacks the extended call gets the plain one. Any other failure (a folder
        // that is no longer empty, a file in use) is reported as it is, and the attributes stay untouched.
        if (err is not (87 or 1 or 50)) return err;
        // Plain disposition cannot ignore read-only: clear it, and put the attributes back if the delete still fails.
        uint before = GetFileAttributesW(FileProbe.Long(path));
        SetFileAttributesW(FileProbe.Long(path), 0x80 /* NORMAL */);
        uint del = 1;
        if (SetFileInformationByHandle(h, FileDispositionInfo, ref del, sizeof(uint))) return 0;
        err = (uint)Marshal.GetLastWin32Error();
        if (before != 0xFFFFFFFF) SetFileAttributesW(FileProbe.Long(path), before);
        return err;
    }

    /// <summary>Always the \\?\ form: Win32 would strip a trailing dot or space from a plain path and write elsewhere.</summary>
    private static string Name(string path) => FileProbe.Long(path);

    /// <summary>Writes the given explicit entries as the object's DACL. Windows adds the inherited entries again
    /// when inheritance is on, and propagates the change to children.</summary>
    internal static uint SetDacl(string path, List<AceInfo> explicitAces, byte revision, bool isProtected)
    {
        int size = 8 + explicitAces.Sum(a => a.Raw.Length);
        var acl = new byte[size];
        acl[0] = Math.Max(revision, (byte)ACL_REVISION);
        BitConverter.GetBytes((ushort)size).CopyTo(acl, 2);
        BitConverter.GetBytes((ushort)explicitAces.Count).CopyTo(acl, 4);
        int pos = 8;
        foreach (var a in explicitAces) { a.Raw.CopyTo(acl, pos); pos += a.Raw.Length; }

        var p = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(acl, 0, p, size);
            uint info = DACL_SECURITY_INFORMATION | (isProtected ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
            return SetNamedSecurityInfoW(Name(path), SE_FILE_OBJECT, info, IntPtr.Zero, IntPtr.Zero, p, IntPtr.Zero);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    /// <summary>The topmost objects whose subtree must be re-read (entry changes propagate downwards).</summary>
    public static IEnumerable<ScanNode> ReprobeRoots(OrphanPlan plan)
    {
        var set = new HashSet<ScanNode>(plan.Entries);
        return plan.Entries.Where(n => !n.Ancestors().Any(set.Contains));
    }
}
