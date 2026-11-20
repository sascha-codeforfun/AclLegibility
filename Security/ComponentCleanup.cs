using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using AclLegibility.Model;

namespace AclLegibility.Security;

/// <summary>What the scan shows about the component store, before anything runs.</summary>
public sealed class ComponentPreview
{
    public required ScanNode WinSxS { get; init; }
    /// <summary>Component folders that have a newer version of the same component (same architecture, name, key, language).</summary>
    public int OlderVersions { get; init; }
    public int Components { get; init; }
    public int Objects { get; init; }
    /// <summary>Size of the older versions as listed. Files shared with Windows through hard links count here too, so freed
    /// space can be less.</summary>
    public long Size { get; init; }
}

public sealed record DismOutcome(int ExitCode, string Output, int ObjectsBefore, int ObjectsAfter);

/// <summary>
/// The fourth action: Windows' own component-store clean-up (DISM /StartComponentCleanup, optionally /ResetBase) on the running
/// Windows. The same step Windows' scheduled servicing task runs, without its 30-day wait. Started by the user from the action
/// row (no scan needed) or the details of %SystemRoot%\WinSxS, after a confirmation. DISM is not interrupted once started.
/// </summary>
public static class ComponentCleanup
{
    private static readonly Regex Component = new(
        @"^(?<arch>amd64|x86|wow64|msil|arm64|arm)_(?<name>.+)_(?<key>[0-9a-f]{16})_(?<ver>\d+\.\d+\.\d+\.\d+)_(?<lang>[^_]+)_[0-9a-f]+$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string? WinSxSPath(ScanResult r) =>
        r.Os.Paths.TryGetValue("SystemRoot", out var sr) ? sr.TrimEnd('\\') + "\\WinSxS" : null;

    public static bool IsWinSxS(ScanResult r, ScanNode n) =>
        WinSxSPath(r) is { } p && string.Equals(n.FullPath.TrimEnd('\\'), p, StringComparison.OrdinalIgnoreCase);

    /// <summary>Null when it can run; otherwise why not. It acts on the running Windows and needs no scan: run it before a
    /// full scan, and the scan does not have to read the superseded versions at all.</summary>
    public static string? WhyNot() => File.Exists(DismPath) ? null : "dism.exe was not found in the system folder.";

    public static string DismPath => Path.Combine(Environment.SystemDirectory, "dism.exe");

    public static string Arguments(bool resetBase) =>
        "/Online /Cleanup-Image /StartComponentCleanup" + (resetBase ? " /ResetBase" : "") + " /English";

    public static ComponentPreview? Preview(ScanResult r)
    {
        if (WinSxSPath(r) is not { } path || r.FindByPath(path) is not { } sxs || sxs.Children == null) return null;
        var groups = new Dictionary<string, List<(ScanNode Node, Version Ver)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in sxs.Children)
        {
            if (!c.IsDirectory) continue;
            var m = Component.Match(c.Name);
            if (!m.Success || !Version.TryParse(m.Groups["ver"].Value, out var v)) continue;
            var key = $"{m.Groups["arch"].Value}|{m.Groups["name"].Value}|{m.Groups["key"].Value}|{m.Groups["lang"].Value}";
            if (!groups.TryGetValue(key, out var list)) groups[key] = list = new();
            list.Add((c, v));
        }
        int older = 0, components = 0, objects = 0; long size = 0;
        foreach (var list in groups.Values.Where(l => l.Count > 1))
        {
            components++;
            var newest = list.Max(x => x.Ver)!;
            foreach (var (node, ver) in list)
            {
                if (ver == newest) continue;
                older++;
                var st = new Stack<ScanNode>(); st.Push(node);
                while (st.Count > 0) { var x = st.Pop(); objects++; size += x.Size; if (x.Children != null) foreach (var y in x.Children) st.Push(y); }
            }
        }
        return new ComponentPreview { WinSxS = sxs, OlderVersions = older, Components = components, Objects = objects, Size = size };
    }

    public static int CountObjects(ScanNode n)
    {
        int count = 0;
        var st = new Stack<ScanNode>(); st.Push(n);
        while (st.Count > 0) { var x = st.Pop(); count++; if (x.Children != null) foreach (var y in x.Children) st.Push(y); }
        return count;
    }

    private static readonly Regex Percent = new(@"(\d+(?:[.,]\d+)?)%", RegexOptions.Compiled);

    /// <summary>Runs DISM and waits for it. Progress lines (DISM redraws them with carriage returns) go to <paramref name="progress"/>
    /// with the percentage when one is shown. There is deliberately no way to cancel: an interrupted DISM run leaves work for the
    /// next servicing operation.</summary>
    public static (int ExitCode, string Output) Run(bool resetBase, Action<string, int?> progress)
    {
        var psi = new ProcessStartInfo(DismPath, Arguments(resetBase))
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("dism.exe could not be started.");
        var all = new StringBuilder();
        var line = new StringBuilder();
        var err = p.StandardError.ReadToEndAsync();
        int ch;
        while ((ch = p.StandardOutput.Read()) >= 0)
        {
            if (ch == '\r' || ch == '\n')
            {
                var text = line.ToString().Trim();
                line.Clear();
                if (text.Length == 0) continue;
                var m = Percent.Match(text);
                int? pct = m.Success && double.TryParse(m.Groups[1].Value.Replace(',', '.'), System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var d) ? (int)Math.Round(d) : null;
                progress(pct != null ? $"Component store clean-up {pct}%" : text, pct);
                if (pct == null) all.AppendLine(text);
            }
            else line.Append((char)ch);
        }
        if (line.ToString().Trim() is { Length: > 0 } last) all.AppendLine(last);   // a last line without a line break
        p.WaitForExit();
        var e = err.Result.Trim();
        if (e.Length > 0) all.AppendLine(e);
        return (p.ExitCode, all.ToString().Trim());
    }
}
