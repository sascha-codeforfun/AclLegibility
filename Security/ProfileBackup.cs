using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using AclLegibility.Model;
using AclLegibility.Native;
using Microsoft.Win32.SafeHandles;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Security;

/// <summary>
/// Saves the personal files of profiles that are about to be deleted into one ZIP, keeping their folder structure
/// under the profile's name ("defaultuser0/Documents/…"). Files are read with backup semantics, so files only the
/// deleted account could open are included. The ZIP is checked after writing — every entry present with its size —
/// and the caller deletes nothing unless this returns normally.
/// </summary>
public static class ProfileBackup
{
    public static (int Files, long Bytes) Write(string zipPath, IEnumerable<ProfilePlan> profiles, Action<int, int, string>? progress = null)
    {
        Privileges.Enable(Privileges.Backup);
        var items = profiles.SelectMany(p => p.PersonalFiles.Select(f => (Profile: p, File: f))).ToList();
        // Names keep their case: a case-sensitive folder can hold Notes.txt and notes.txt side by side.
        var expected = new Dictionary<string, long>(StringComparer.Ordinal);
        using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            int i = 0;
            foreach (var (p, f) in items)
            {
                progress?.Invoke(++i, items.Count, f.FullPath);
                var profileName = Path.GetFileName(p.Path.TrimEnd('\\'));
                var rel = f.FullPath.Length > p.Path.Length ? f.FullPath[(p.Path.Length + 1)..] : f.Name;
                var name = (profileName + "/" + rel.Replace('\\', '/'));
                var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var src = OpenForBackup(f.FullPath);
                using var dst = entry.Open();
                src.CopyTo(dst);
                expected[name] = src.Length;
            }
        }

        // verify: reopen, every entry there with the size that was read
        using (var check = ZipFile.OpenRead(zipPath))
        {
            var found = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var e in check.Entries) found[e.FullName] = e.Length;
            foreach (var (name, len) in expected)
                if (!found.TryGetValue(name, out var got) || got != len)
                    throw new IOException($"The ZIP backup could not be verified ({name}). Nothing was deleted.");
        }
        return (expected.Count, expected.Values.Sum());
    }

    private static FileStream OpenForBackup(string path)
    {
        var h = CreateFileW(FileProbe.Long(path), GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
        if (h.IsInvalid)
            throw new IOException($"Could not read {path} for the backup (error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}). Nothing was deleted.");
        return new FileStream(h, FileAccess.Read);
    }
}
