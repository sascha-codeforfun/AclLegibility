using System;
using System.Collections.Generic;
using System.Linq;
using AclLegibility.Model;
using Microsoft.Win32;

namespace AclLegibility.Security;

/// <summary>A place that may hold a Windows installation or image other than the running one.</summary>
/// <param name="Path">The folder the question is about: a drive root, a mount folder, Windows.old, …</param>
/// <param name="Evidence">What was found, in plain words — never a conclusion.</param>
public sealed record ForeignPlace(string Path, string Evidence);

/// <summary>
/// Finds places that may be another Windows: a folder holding <c>Windows\System32</c> other than the running Windows
/// (a second drive, Windows.old, a DISM mount folder), and every image DISM itself records as mounted. The app never
/// decides what such a place is: the actions that change something ask, and leave a place alone when the answer is yes.
/// </summary>
public static class ForeignWindows
{
    /// <summary>Every candidate in the scan, plus DISM's record of mounted images (read on a live scan only).</summary>
    public static List<ForeignPlace> Find(ScanResult r)
    {
        var found = new Dictionary<string, ForeignPlace>(StringComparer.OrdinalIgnoreCase);
        r.Os.Paths.TryGetValue("SystemRoot", out var sysRoot);
        var running = sysRoot?.TrimEnd('\\');

        foreach (var n in r.AllNodes())
        {
            if (!n.IsDirectory || n.Extra?.Reparse != null || !n.Name.Equals("Windows", StringComparison.OrdinalIgnoreCase)) continue;
            if (n.Children?.Any(c => c.IsDirectory && c.Name.Equals("System32", StringComparison.OrdinalIgnoreCase)) != true) continue;
            var windows = n.FullPath.TrimEnd('\\');
            if (running != null && (windows.Equals(running, StringComparison.OrdinalIgnoreCase) || Under(windows, running))) continue;
            var place = n.Parent?.FullPath ?? windows;
            found.TryAdd(place, new ForeignPlace(place, $"holds a Windows folder ({windows}\\System32)"));
        }

        if (r.IsLive)
            foreach (var (mount, image, index) in MountedImages())
            {
                var evidence = "is an image mounted by DISM (" + image + (index != null ? ", index " + index : "") + ")";
                found[mount] = found.TryGetValue(mount, out var had)
                    ? had with { Evidence = evidence + "; it " + had.Evidence }
                    : new ForeignPlace(mount, evidence);
            }
        return found.Values.OrderBy(p => p.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>DISM's own record of mounted images: HKLM\SOFTWARE\Microsoft\WIMMount\Mounted Images (read only).</summary>
    public static List<(string Mount, string Image, string? Index)> MountedImages()
    {
        var list = new List<(string, string, string?)>();
        if (!OperatingSystem.IsWindows()) return list;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\WIMMount\Mounted Images");
            if (key == null) return list;
            foreach (var name in key.GetSubKeyNames())
            {
                using var k = key.OpenSubKey(name);
                if (k?.GetValue("Mount Path") is not string mount || mount.Length == 0) continue;
                var image = k.GetValue("Image Path") as string ?? "image";
                var index = k.GetValue("Image Index")?.ToString();
                list.Add((mount.TrimEnd('\\').Length <= 2 ? mount.TrimEnd('\\') + "\\" : mount.TrimEnd('\\'), image, index));
            }
        }
        catch { /* no record readable: nothing reported from it */ }
        return list;
    }

    /// <summary>The places that contain at least one of the given objects (or contain everything because they sit above them).</summary>
    public static List<ForeignPlace> Touching(IEnumerable<ForeignPlace> places, IEnumerable<ScanNode> nodes)
    {
        var list = places.ToList();
        if (list.Count == 0) return list;
        var hit = new HashSet<ForeignPlace>();
        foreach (var n in nodes)
        {
            var path = n.FullPath;
            foreach (var p in list)
                if (!hit.Contains(p) && Contains(p.Path, path)) hit.Add(p);
            if (hit.Count == list.Count) break;
        }
        return list.Where(hit.Contains).ToList();
    }

    /// <summary>The place (from <paramref name="leaveAlone"/>) that holds this path, or null.</summary>
    public static string? HolderOf(string path, IReadOnlyCollection<string>? leaveAlone)
    {
        if (leaveAlone == null) return null;
        foreach (var p in leaveAlone) if (Contains(p, path)) return p;
        return null;
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="place"/> or lies below it.</summary>
    public static bool Contains(string place, string path)
    {
        var a = place.TrimEnd('\\');
        var b = path.TrimEnd('\\');
        return b.Equals(a, StringComparison.OrdinalIgnoreCase) || Under(b, a);
    }

    private static bool Under(string path, string folder) =>
        path.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
}
