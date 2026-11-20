using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AclLegibility.Model;

namespace AclLegibility.Security;

/// <summary>Backups in icacls /save format, so they restore without the app:
/// UTF-16, one line with the path relative to a base folder, one line with the DACL in SDDL.</summary>
public static class IcaclsBackup
{
    private static readonly UnicodeEncoding Encoding = new(bigEndian: false, byteOrderMark: false);

    public static string Relative(string restoreBase, ScanNode n)
    {
        var full = n.FullPath;
        var b = restoreBase.TrimEnd('\\');
        return full.Length > b.Length + 1 ? full.Substring(b.Length + 1) : full;
    }

    /// <summary>The node is the restore base itself — in practice a drive root.</summary>
    public static bool IsBase(string restoreBase, ScanNode n) =>
        string.Equals(n.FullPath.TrimEnd('\\'), restoreBase.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Where the restore line for the base itself goes, next to the icacls file. icacls /save writes an empty name
    /// line for the folder it starts from, but icacls /restore cannot read that line back: it takes the SDDL for the name
    /// and every entry after it fails (tested on Windows 11 26H2). So the base is restored with PowerShell instead.</summary>
    public static string RootFile(string file) =>
        Path.Combine(Path.GetDirectoryName(file) ?? "", Path.GetFileNameWithoutExtension(file) + "-root.txt");

    /// <summary>Writes the current DACLs and reads the file back; throws if it is not complete.
    /// Called before anything is changed, so a failure leaves the system untouched. Everything below the base goes into the
    /// icacls file; the base itself (a drive root) goes into <see cref="RootFile"/> as one PowerShell line.</summary>
    public static void Write(ScanResult r, IReadOnlyList<ScanNode> nodes, string restoreBase, string file)
    {
        var sb = new StringBuilder();
        int count = 0;
        string? rootSddl = null;
        foreach (var n in nodes)
        {
            var sd = r.SdOf(n) ?? throw new InvalidOperationException("Permissions of " + n.FullPath + " are not known; nothing was changed.");
            if (IsBase(restoreBase, n)) { rootSddl = sd.DaclSddl; continue; }
            sb.Append(Relative(restoreBase, n)).Append("\r\n").Append(sd.DaclSddl).Append("\r\n");
            count++;
        }
        File.WriteAllText(file, sb.ToString(), Encoding);
        var rootFile = RootFile(file);
        if (rootSddl != null) File.WriteAllText(rootFile, RootLine(restoreBase, rootSddl) + "\r\n", System.Text.Encoding.UTF8);
        else if (File.Exists(rootFile)) File.Delete(rootFile);   // a stale one from an earlier backup of the same name

        var back = File.ReadAllText(file, Encoding).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (back.Length != count * 2)
            throw new IOException($"The backup file has {back.Length / 2} entries instead of {count}; nothing was changed.");
        for (int i = 1; i < back.Length; i += 2)
            if (!back[i].StartsWith("D:", StringComparison.Ordinal))
                throw new IOException("The backup file could not be verified; nothing was changed.");
        if (rootSddl != null && !File.ReadAllText(rootFile).Contains(rootSddl, StringComparison.Ordinal))
            throw new IOException("The backup of " + restoreBase + " could not be verified; nothing was changed.");
    }

    /// <summary>One PowerShell line that puts a drive root's DACL back. The entries come back as saved; .NET writes them in
    /// canonical order and marks the list auto-inherited (AI), so the result is equivalent, not byte-identical.</summary>
    private static string RootLine(string restoreBase, string sddl)
    {
        var b = restoreBase.TrimEnd('\\') + "\\";
        return $"$a = Get-Acl -LiteralPath '{b}'; $a.SetSecurityDescriptorSddlForm('{sddl}', 'Access'); Set-Acl -LiteralPath '{b}' -AclObject $a";
    }

    /// <summary>What to run to restore: the icacls line when the file holds entries, and the PowerShell line for the drive
    /// root when it was saved too. Both in an elevated PowerShell.</summary>
    public static string RestoreCommand(string restoreBase, string file)
    {
        var lines = new List<string>();
        if (!File.Exists(file) || new FileInfo(file).Length > 0)
        {
            // A drive root must keep its backslash and must not be quoted ("D:\" would escape the quote).
            var b = restoreBase.TrimEnd('\\');
            var target = b.Length <= 2 ? b + "\\" : $"\"{b}\"";
            lines.Add($"icacls {target} /restore \"{file}\" /c");
        }
        var rootFile = RootFile(file);
        if (File.Exists(rootFile)) lines.Add(File.ReadAllText(rootFile).Trim());
        return string.Join("\n", lines);
    }
}
