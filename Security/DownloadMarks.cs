using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using AclLegibility.Model;
using AclLegibility.Native;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Security;

/// <summary>One file below the chosen folder that carries a download mark (a Zone.Identifier stream).</summary>
public sealed class MarkedFile
{
    public required ScanNode Node { get; init; }
    /// <summary>The zone the mark names (3 = Internet), or null when the mark could not be read or names none.</summary>
    public int? Zone { get; init; }
    /// <summary>Where it came from, when the mark says (HostUrl, else ReferrerUrl): the host only.</summary>
    public string? Host { get; init; }
    /// <summary>A program, script, installer, shortcut or macro-capable document: for those the mark is what makes
    /// SmartScreen, Smart App Control or Office check them, so removing it is never the default.</summary>
    public bool IsProgram { get; init; }
}

/// <summary>Files grouped by what their mark says.</summary>
public sealed class MarkGroup
{
    public required string Key { get; init; }
    public required string Title { get; init; }
    public required string Explain { get; init; }
    /// <summary>Whether the group is ticked when the preview opens (data files only; programs have one tick of their own).</summary>
    public bool TickedByDefault { get; init; }
    public List<MarkedFile> Files { get; } = new();
}

public sealed class MarksPlan
{
    public required ScanNode Folder { get; init; }
    /// <summary>Data files, one group per kind of mark.</summary>
    public List<MarkGroup> Groups { get; } = new();
    /// <summary>Programs and scripts, split the same way; shown as one card with one tick.</summary>
    public List<MarkGroup> Programs { get; } = new();
    public int DataCount => Groups.Sum(g => g.Files.Count);
    public int ProgramCount => Programs.Sum(g => g.Files.Count);
    public int Count => DataCount + ProgramCount;
}

public sealed record MarksOutcome(int Removed, int AlreadyGone, List<(string Path, string Error)> Failed, bool Cancelled);

/// <summary>
/// The sixth action: removes download marks (Mark of the Web — the Zone.Identifier stream) below a folder, by location.
/// Only that stream is deleted; the file's content, other streams, security and object ID stay, and its time stamps are
/// put back exactly as they were. Nothing can be restored: a mark comes back only with a new download.
/// </summary>
public static class DownloadMarks
{
    public const string StreamName = "Zone.Identifier";

    private static readonly HashSet<string> ProgramExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle", ".appinstaller",
        ".application", ".appref-ms", ".dll", ".ocx", ".sys", ".drv", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".ps1xml",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg", ".inf", ".msc", ".chm", ".jar",
        ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm", ".doc", ".dot", ".xls",
        ".xlt", ".xla", ".ppt", ".pot", ".pps", ".iso", ".img", ".vhd", ".vhdx",
    };

    // What the mark does, where it fails and what the baselines require — side by side, so the reader decides.
    // Shown in a file's stream details, in the preview and in the README.

    public const string Does =
        "Windows blocks a file that carries the mark: SmartScreen and Smart App Control check a program before it runs, Office opens "
        + "a document read-only in Protected View, without macros, data connections or Power Query, and \"Unblock\" in the file's "
        + "Properties removes the mark.";

    public const string Fails =
        "It is lost when a file is copied to a disk that is not NTFS (FAT32, exFAT, many shares and sync tools), and usually when a "
        + "third-party tool unpacks an archive. Writing it is voluntary: browsers and mail clients do, curl, git, package managers and "
        + "the self-updaters of conferencing and remote-support tools usually do not, and signed code passes SmartScreen on its "
        + "reputation anyway. It matters at the first double-click after a browser or mail download; on files that have been on "
        + "disk for months it is noise rather than protection.";

    public const string Policy =
        "The policy \"Do not preserve zone information in file attachments\" (User Configuration › Administrative Templates › "
        + "Windows Components › Attachment Manager) stops new marks altogether. The app does not change it.";

    public const string Baselines =
        "Formal baselines take the opposite view: the DISA STIG and the CIS Benchmark both require the mark to be kept, and enabling "
        + "\"Do not preserve zone information in file attachments\" is a medium (CAT II) STIG finding — though CIS's own text concedes "
        + "the mark works only on NTFS and is lost without notice on FAT32.";

    public static bool IsProgram(string name) => ProgramExtensions.Contains(Path.GetExtension(name));

    /// <summary>Null when it can run here; otherwise why not.</summary>
    public static string? WhyNot(ScanResult r, ScanNode folder)
    {
        if (!r.IsLive) return "Only for a scan of this machine, not for a snapshot.";
        if (!folder.IsDirectory) return "Only for folders and drives.";
        return null;
    }

    /// <summary>Every file below the folder whose scan shows a Zone.Identifier stream, its mark read now and grouped.
    /// Null when cancelled.</summary>
    public static MarksPlan? Plan(ScanResult r, ScanNode folder, Action<string, int, int> progress, CancellationToken ct)
    {
        // The scan already knows which files carry the stream, so the total is known before reading starts.
        var candidates = new List<ScanNode>();
        var stack = new Stack<ScanNode>();
        stack.Push(folder);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n.Children != null) foreach (var c in n.Children) stack.Push(c);
            if (!n.IsDirectory && n.Extra?.Streams?.Any(s => s.Name.Equals(StreamName, StringComparison.OrdinalIgnoreCase)) == true)
                candidates.Add(n);
        }
        candidates.Sort((a, b) => string.Compare(a.FullPath, b.FullPath, StringComparison.OrdinalIgnoreCase));

        var plan = new MarksPlan { Folder = folder };
        var data = new Dictionary<string, MarkGroup>(StringComparer.OrdinalIgnoreCase);
        var programs = new Dictionary<string, MarkGroup>(StringComparer.OrdinalIgnoreCase);
        var tick = Stopwatch.StartNew();
        for (int i = 0; i < candidates.Count; i++)
        {
            if (ct.IsCancellationRequested) return null;
            var n = candidates[i];
            if (i == 0 || tick.ElapsedMilliseconds >= 100) { progress(n.FullPath, i, candidates.Count); tick.Restart(); }
            var text = LiveReads.ReadStreamText(n.FullPath, StreamName, 4096, out _, out var binary);
            var (zone, host) = binary || text.StartsWith("(could not open", StringComparison.Ordinal) ? (null, null) : Parse(text);
            var file = new MarkedFile { Node = n, Zone = zone, Host = host, IsProgram = IsProgram(n.Name) };
            GroupFor(file, file.IsProgram ? programs : data).Files.Add(file);
        }
        progress("", candidates.Count, candidates.Count);
        plan.Groups.AddRange(Order(data.Values));
        plan.Programs.AddRange(Order(programs.Values));
        return plan;
    }

    private static IEnumerable<MarkGroup> Order(IEnumerable<MarkGroup> groups) => groups
        .OrderBy(g => g.Key == "bare" ? 0 : g.Key.StartsWith("source:", StringComparison.Ordinal) ? 1 : 2)
        .ThenByDescending(g => g.Files.Count);

    private static MarkGroup GroupFor(MarkedFile f, Dictionary<string, MarkGroup> groups)
    {
        string key; string title; string explain; bool ticked;
        if (f.Zone == 3 && f.Host == null)
        {
            key = "bare"; title = "Bare mark — Internet zone, no source"; ticked = true;
            explain = "[ZoneTransfer] ZoneId=3 and nothing else. Usually written when files are extracted with Windows' own zip "
                      + "handling from an archive that had a mark: the zip's mark is copied onto the file types Windows treats as risky "
                      + "(programs, libraries, scripts, disk images, archives), without a source. Data files from the same archive stay unmarked.";
        }
        else if (f.Zone == 3)
        {
            key = "source:" + f.Host; title = "Downloaded from " + f.Host; ticked = true;
            explain = "The mark names where the file came from (HostUrl or ReferrerUrl).";
        }
        else if (f.Zone is { } z)
        {
            key = "zone:" + z; ticked = false;
            title = z switch
            {
                0 => "Zone 0 — this computer",
                1 => "Zone 1 — local intranet",
                2 => "Zone 2 — trusted sites",
                4 => "Zone 4 — restricted sites",
                _ => $"Zone {z}",
            };
            explain = z == 4
                ? "Marked as coming from a restricted site — someone or something distrusted its source on purpose. Not ticked."
                : "A zone other than Internet. Not ticked: the mark does something different from the usual download mark.";
        }
        else
        {
            key = "unreadable"; title = "Mark not readable or without a zone"; ticked = false;
            explain = "The stream exists but its content could not be read now, or names no zone. Not ticked.";
        }
        if (!groups.TryGetValue(key, out var g))
            groups[key] = g = new MarkGroup { Key = key, Title = title, Explain = explain, TickedByDefault = ticked };
        return g;
    }

    /// <summary>ZoneId and the source host from a Zone.Identifier's text.</summary>
    public static (int? Zone, string? Host) Parse(string text)
    {
        int? zone = null; string? host = null, referrer = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, out var z)) zone = z;
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) host = HostOf(value);
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) referrer = HostOf(value);
        }
        return (zone, host ?? referrer);
    }

    private static string? HostOf(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host)) return u.Host.ToLowerInvariant();
        return url.Length == 0 ? null : (url.Length > 60 ? url[..60] + "…" : url);
    }

    /// <summary>Deletes the Zone.Identifier stream of each file and puts the file's time stamps back as they were.</summary>
    public static MarksOutcome Run(IReadOnlyList<MarkedFile> files, Action<string, int, int> progress, CancellationToken ct)
    {
        Privileges.EnableReadPrivileges();
        Privileges.Enable(Privileges.Restore);
        var failed = new List<(string, string)>();
        int removed = 0, gone = 0, i = 0;
        var tick = Stopwatch.StartNew();
        foreach (var f in files)
        {
            if (ct.IsCancellationRequested) return new(removed, gone, failed, true);
            if (i++ == 0 || tick.ElapsedMilliseconds >= 100) { progress(f.Node.FullPath, i, files.Count); tick.Restart(); }
            var err = RemoveMark(f.Node.FullPath);
            if (err == 0) removed++;
            else if (err == 2 || err == 3) gone++;
            else failed.Add((f.Node.FullPath, $"error {err} ({new System.ComponentModel.Win32Exception((int)err).Message})"));
        }
        progress("", files.Count, files.Count);
        return new(removed, gone, failed, false);
    }

    /// <summary>0 when the mark was removed; 2 when there was none any more; otherwise the Windows error.</summary>
    internal static unsafe uint RemoveMark(string path)
    {
        var longPath = FileProbe.Long(path);
        // The file's time stamps first: deleting a stream changes them, and they are put back afterwards.
        using var file = CreateFileW(longPath, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (file.IsInvalid) return (uint)Marshal.GetLastWin32Error();
        byte* basic = stackalloc byte[40];
        bool haveTimes = GetFileInformationByHandleEx(file, 0 /* FileBasicInfo */, basic, 40);

        uint result;
        using (var stream = CreateFileW(longPath + ":" + StreamName, DELETE, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
        {
            if (stream.IsInvalid) return (uint)Marshal.GetLastWin32Error();
            // A read-only file refuses deletes, and removing a stream counts as one. The newer call can ignore the
            // attribute without clearing it (Windows 10 1809 and later); the attribute stays as it was.
            uint flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
            if (SetFileInformationByHandle(stream, FileDispositionInfoEx, ref flags, sizeof(uint))) result = 0;
            else
            {
                result = (uint)Marshal.GetLastWin32Error();
                if (result is 87 or 1 or 50)   // older Windows: no extended call; the plain one cannot ignore read-only
                {
                    uint del = 1;
                    result = SetFileInformationByHandle(stream, FileDispositionInfo, ref del, sizeof(uint)) ? 0 : (uint)Marshal.GetLastWin32Error();
                }
            }
        }   // the stream goes when its handle closes

        if (result == 0 && haveTimes)
        {
            *(uint*)(basic + 32) = 0;   // attributes: 0 = leave as they are
            SetFileInformationByHandlePtr(file, 0 /* FileBasicInfo */, basic, 40);
        }
        return result;
    }
}
