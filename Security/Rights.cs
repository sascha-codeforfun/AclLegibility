using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AclLegibility.Security;

/// <summary>File system access-mask helpers.</summary>
public static class Rights
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint GENERIC_EXECUTE = 0x20000000;
    public const uint GENERIC_ALL = 0x10000000;
    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public const uint ACCESS_SYSTEM_SECURITY = 0x01000000;

    public const uint FILE_GENERIC_READ = 0x00120089;
    public const uint FILE_GENERIC_WRITE = 0x00120116;
    public const uint FILE_GENERIC_EXECUTE = 0x001200A0;
    public const uint FILE_ALL_ACCESS = 0x001F01FF;

    public const uint Full = 0x001F01FF;
    public const uint Modify = 0x001301BF;
    public const uint ReadExecute = 0x001200A9;
    public const uint Read = 0x00120089;
    public const uint Write = 0x00100116;

    /// <summary>Maps generic bits onto file-specific rights so "GR,GE" and "RX" compare equal.</summary>
    public static uint Normalize(uint mask)
    {
        uint m = mask & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        if ((mask & GENERIC_READ) != 0) m |= FILE_GENERIC_READ;
        if ((mask & GENERIC_WRITE) != 0) m |= FILE_GENERIC_WRITE;
        if ((mask & GENERIC_EXECUTE) != 0) m |= FILE_GENERIC_EXECUTE;
        if ((mask & GENERIC_ALL) != 0) m |= FILE_ALL_ACCESS;
        return m;
    }

    private static readonly (uint Bit, string Short, string File, string Dir)[] Bits =
    {
        (0x00000001, "RD", "Read data", "List folder"),
        (0x00000002, "WD", "Write data", "Create files"),
        (0x00000004, "AD", "Append data", "Create folders"),
        (0x00000008, "REA", "Read extended attributes", "Read extended attributes"),
        (0x00000010, "WEA", "Write extended attributes", "Write extended attributes"),
        (0x00000020, "X", "Execute", "Traverse folder"),
        (0x00000040, "DC", "Delete child", "Delete subfolders and files"),
        (0x00000080, "RA", "Read attributes", "Read attributes"),
        (0x00000100, "WA", "Write attributes", "Write attributes"),
        (0x00010000, "DE", "Delete", "Delete"),
        (0x00020000, "RC", "Read permissions", "Read permissions"),
        (0x00040000, "WDAC", "Change permissions", "Change permissions"),
        (0x00080000, "WO", "Take ownership", "Take ownership"),
        (0x00100000, "S", "Synchronize", "Synchronize"),
        (0x01000000, "AS", "Access system security", "Access system security"),
        (0x02000000, "MA", "Maximum allowed", "Maximum allowed"),
        (0x10000000, "GA", "Generic all", "Generic all"),
        (0x20000000, "GE", "Generic execute", "Generic execute"),
        (0x40000000, "GW", "Generic write", "Generic write"),
        (0x80000000, "GR", "Generic read", "Generic read"),
    };

    private static readonly Dictionary<string, uint> Tokens = BuildTokens();

    private static Dictionary<string, uint> BuildTokens()
    {
        var d = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase)
        {
            ["F"] = Full, ["M"] = Modify, ["RX"] = ReadExecute, ["R"] = Read, ["W"] = Write,
        };
        foreach (var b in Bits) d[b.Short] = b.Bit;
        return d;
    }

    /// <summary>Parses "F", "RX", "RD+S", "0x1200a9" style tokens. Returns null when invalid.</summary>
    public static uint? Parse(string text)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) ? hex : null;
        uint m = 0;
        foreach (var part in text.Split('+', ',', '|'))
        {
            if (!Tokens.TryGetValue(part.Trim(), out var v)) return null;
            m |= v;
        }
        return m;
    }

    /// <summary>Short icacls-like text, e.g. "F", "M", "RX", "RD,S".</summary>
    public static string Short(uint mask)
    {
        uint n = Normalize(mask);
        string? named = n switch
        {
            Full => "F", Modify => "M", ReadExecute => "RX", Read => "R", Write => "W", _ => null,
        };
        if (named != null) return named;
        // common composites
        if ((n & Modify) == Modify && n != Modify) return "M+" + BitsText(n & ~Modify, true);
        if ((n & ReadExecute) == ReadExecute && n != ReadExecute) return "RX+" + BitsText(n & ~ReadExecute, true);
        return BitsText(mask, true);
    }

    public static string Long(uint mask, bool isDirectory)
    {
        uint n = Normalize(mask);
        string? named = n switch
        {
            Full => "Full control",
            Modify => "Modify",
            ReadExecute => isDirectory ? "Read & execute / list folder" : "Read & execute",
            Read => "Read",
            Write => "Write",
            _ => null,
        };
        if (named != null) return named;
        var parts = new List<string>();
        foreach (var b in Bits)
            if ((n & b.Bit) != 0) parts.Add(isDirectory ? b.Dir : b.File);
        return parts.Count == 0 ? "(none)" : string.Join(", ", parts);
    }

    private static string BitsText(uint mask, bool shortNames)
    {
        var parts = new List<string>();
        foreach (var b in Bits)
            if ((mask & b.Bit) != 0) parts.Add(shortNames ? b.Short : b.File);
        return parts.Count == 0 ? "0x" + mask.ToString("x") : string.Join(",", parts);
    }

    public static string Hex(uint mask) => "0x" + mask.ToString("x8");

    public static string InheritShort(AceFlags f)
    {
        var sb = new StringBuilder();
        if ((f & AceFlags.ObjectInherit) != 0) sb.Append("(OI)");
        if ((f & AceFlags.ContainerInherit) != 0) sb.Append("(CI)");
        if ((f & AceFlags.InheritOnly) != 0) sb.Append("(IO)");
        if ((f & AceFlags.NoPropagateInherit) != 0) sb.Append("(NP)");
        return sb.ToString();
    }

    /// <summary>"Applies to" as shown in the Windows Advanced Security dialog.</summary>
    /// <summary>Everyone, Authenticated Users, Users, SYSTEM, Administrators: a Deny for one of these locks out nearly everyone.</summary>
    public static readonly HashSet<string> BroadPrincipals = new(StringComparer.OrdinalIgnoreCase)
        { "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-18", "S-1-5-32-544" };

    /// <summary>An explicit (not inherited) Deny entry for a broad principal.</summary>
    public static bool IsBroadDeny(AceInfo a) => a.IsDeny && !a.IsInherited && BroadPrincipals.Contains(a.Sid);

    public static string AppliesTo(AceFlags f, bool isDirectory)
    {
        // On a file, an inherit-only entry applies to nothing: a file has no children to pass it to, and Windows ignores it
        // (it appears when a folder's descriptor is written onto a file as it is).
        if (!isDirectory) return (f & AceFlags.InheritOnly) != 0 ? "Nothing — inherit-only on a file, Windows ignores it" : "This file";
        bool oi = (f & AceFlags.ObjectInherit) != 0, ci = (f & AceFlags.ContainerInherit) != 0;
        bool io = (f & AceFlags.InheritOnly) != 0, np = (f & AceFlags.NoPropagateInherit) != 0;
        string s = (oi, ci, io) switch
        {
            (false, false, _) => "This folder only",
            (true, true, false) => "This folder, subfolders and files",
            (false, true, false) => "This folder and subfolders",
            (true, false, false) => "This folder and files",
            (true, true, true) => "Subfolders and files only",
            (false, true, true) => "Subfolders only",
            (true, false, true) => "Files only",
        };
        if (np && (oi || ci)) s += " (one level only)";
        return s;
    }

    public static string LabelLevel(string sid) => sid switch
    {
        "S-1-16-0" => "Untrusted",
        "S-1-16-4096" => "Low",
        "S-1-16-8192" => "Medium",
        "S-1-16-8448" => "Medium Plus",
        "S-1-16-12288" => "High",
        "S-1-16-16384" => "System",
        "S-1-16-20480" => "Protected process",
        _ => sid,
    };

    public static string LabelPolicy(uint mask)
    {
        var p = new List<string>();
        if ((mask & 1) != 0) p.Add("no write-up");
        if ((mask & 2) != 0) p.Add("no read-up");
        if ((mask & 4) != 0) p.Add("no execute-up");
        return p.Count == 0 ? "no policy" : string.Join(", ", p);
    }
}
