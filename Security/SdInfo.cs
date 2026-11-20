using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace AclLegibility.Security;

public static class AceTypes
{
    public const byte AccessAllowed = 0x0;
    public const byte AccessDenied = 0x1;
    public const byte SystemAudit = 0x2;
    public const byte SystemAlarm = 0x3;
    public const byte AccessAllowedCompound = 0x4;
    public const byte AccessAllowedObject = 0x5;
    public const byte AccessDeniedObject = 0x6;
    public const byte SystemAuditObject = 0x7;
    public const byte SystemAlarmObject = 0x8;
    public const byte AccessAllowedCallback = 0x9;
    public const byte AccessDeniedCallback = 0xA;
    public const byte AccessAllowedCallbackObject = 0xB;
    public const byte AccessDeniedCallbackObject = 0xC;
    public const byte SystemAuditCallback = 0xD;
    public const byte SystemAlarmCallback = 0xE;
    public const byte SystemAuditCallbackObject = 0xF;
    public const byte SystemAlarmCallbackObject = 0x10;
    public const byte SystemMandatoryLabel = 0x11;
    public const byte SystemResourceAttribute = 0x12;
    public const byte SystemScopedPolicyId = 0x13;
    public const byte SystemProcessTrustLabel = 0x14;
    public const byte SystemAccessFilter = 0x15;

    public static bool IsAllow(byte t) => t is AccessAllowed or AccessAllowedObject or AccessAllowedCallback or AccessAllowedCallbackObject or AccessAllowedCompound;
    public static bool IsDeny(byte t) => t is AccessDenied or AccessDeniedObject or AccessDeniedCallback or AccessDeniedCallbackObject;
    public static bool IsAudit(byte t) => t is SystemAudit or SystemAuditObject or SystemAuditCallback or SystemAuditCallbackObject or SystemAlarm or SystemAlarmObject or SystemAlarmCallback or SystemAlarmCallbackObject;
    public static bool IsCallback(byte t) => t is AccessAllowedCallback or AccessDeniedCallback or AccessAllowedCallbackObject or AccessDeniedCallbackObject or SystemAuditCallback or SystemAuditCallbackObject or SystemAlarmCallback or SystemAlarmCallbackObject;
    public static bool IsObject(byte t) => t is AccessAllowedObject or AccessDeniedObject or SystemAuditObject or SystemAlarmObject or AccessAllowedCallbackObject or AccessDeniedCallbackObject or SystemAuditCallbackObject or SystemAlarmCallbackObject;

    public static string Name(byte t) => t switch
    {
        AccessAllowed => "Allow",
        AccessDenied => "Deny",
        SystemAudit => "Audit",
        SystemAlarm => "Alarm",
        AccessAllowedCompound => "Allow (compound)",
        AccessAllowedObject => "Allow (object)",
        AccessDeniedObject => "Deny (object)",
        SystemAuditObject => "Audit (object)",
        AccessAllowedCallback => "Allow (conditional)",
        AccessDeniedCallback => "Deny (conditional)",
        AccessAllowedCallbackObject => "Allow (conditional object)",
        AccessDeniedCallbackObject => "Deny (conditional object)",
        SystemAuditCallback => "Audit (conditional)",
        SystemMandatoryLabel => "Integrity label",
        SystemResourceAttribute => "Resource attribute",
        SystemScopedPolicyId => "Central access policy",
        SystemProcessTrustLabel => "Process trust label",
        SystemAccessFilter => "Access filter",
        _ => $"Type 0x{t:X2}",
    };
}

[Flags]
public enum AceFlags : byte
{
    None = 0,
    ObjectInherit = 0x01,
    ContainerInherit = 0x02,
    NoPropagateInherit = 0x04,
    InheritOnly = 0x08,
    Inherited = 0x10,
    SuccessfulAccess = 0x40,
    FailedAccess = 0x80,
}

public sealed class AceInfo
{
    public byte Type { get; init; }
    public AceFlags Flags { get; init; }
    public uint Mask { get; init; }
    public string Sid { get; init; } = "";
    public bool HasCondition { get; init; }
    public Guid? ObjectType { get; init; }
    public Guid? InheritedObjectType { get; init; }
    public int Index { get; init; }
    /// <summary>The ACE exactly as stored (header included) — used to rebuild an ACL without changing other entries.</summary>
    public byte[] Raw { get; init; } = Array.Empty<byte>();

    public bool IsInherited => (Flags & AceFlags.Inherited) != 0;
    public bool IsInheritOnly => (Flags & AceFlags.InheritOnly) != 0;
    public bool IsAllow => AceTypes.IsAllow(Type);
    public bool IsDeny => AceTypes.IsDeny(Type);
    public bool IsAudit => AceTypes.IsAudit(Type);
    public bool IsLabel => Type == AceTypes.SystemMandatoryLabel;
    public uint NormalizedMask => Rights.Normalize(Mask);

    /// <summary>Inheritance bits only (OI, CI, NP, IO) — used for comparisons.</summary>
    public AceFlags InheritanceFlags => Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.NoPropagateInherit | AceFlags.InheritOnly);

    public string TypeName => AceTypes.Name(Type);
}

/// <summary>Parsed self-relative security descriptor. Parsing is done here (not via
/// System.Security.AccessControl) so every ACE type, including labels and claims, stays visible.</summary>
public sealed class SdInfo
{
    public const ushort SE_DACL_PRESENT = 0x0004;
    public const ushort SE_DACL_DEFAULTED = 0x0008;
    public const ushort SE_SACL_PRESENT = 0x0010;
    public const ushort SE_DACL_AUTO_INHERIT_REQ = 0x0100;
    public const ushort SE_SACL_AUTO_INHERIT_REQ = 0x0200;
    public const ushort SE_DACL_AUTO_INHERITED = 0x0400;
    public const ushort SE_SACL_AUTO_INHERITED = 0x0800;
    public const ushort SE_DACL_PROTECTED = 0x1000;
    public const ushort SE_SACL_PROTECTED = 0x2000;

    public byte[] Raw { get; }
    public ushort Control { get; private set; }
    public string? Owner { get; private set; }
    public string? Group { get; private set; }
    public List<AceInfo>? Dacl { get; private set; }     // null = no DACL present (NULL DACL: everyone has full access)
    public byte DaclRevision { get; private set; } = 2;
    public List<AceInfo>? Sacl { get; private set; }
    public string? ParseError { get; private set; }

    public bool DaclPresent => (Control & SE_DACL_PRESENT) != 0;
    public bool SaclPresent => (Control & SE_SACL_PRESENT) != 0;
    public bool DaclProtected => (Control & SE_DACL_PROTECTED) != 0;
    public bool SaclProtected => (Control & SE_SACL_PROTECTED) != 0;
    public bool DaclAutoInherited => (Control & SE_DACL_AUTO_INHERITED) != 0;
    public bool NullDacl => DaclPresent && Dacl == null;

    public AceInfo? Label => Sacl?.FirstOrDefault(a => a.IsLabel);
    public IEnumerable<AceInfo> AuditAces => Sacl?.Where(a => !a.IsLabel) ?? Enumerable.Empty<AceInfo>();

    public bool HasExplicitDaclAce => Dacl?.Any(a => !a.IsInherited) == true;
    public bool HasExplicitSaclAce => AuditAces.Any(a => !a.IsInherited);
    public bool HasExplicitLabel => Label is { IsInherited: false };

    /// <summary>The object does not simply inherit: something was set on it directly.</summary>
    public bool IsBreakpoint => DaclProtected || HasExplicitDaclAce || HasExplicitSaclAce || HasExplicitLabel || NullDacl;

    public IEnumerable<AceInfo> ExplicitDaclAces => Dacl?.Where(a => !a.IsInherited) ?? Enumerable.Empty<AceInfo>();

    public IEnumerable<string> AllSids()
    {
        if (Owner != null) yield return Owner;
        if (Group != null) yield return Group;
        if (Dacl != null) foreach (var a in Dacl) yield return a.Sid;
        if (Sacl != null) foreach (var a in Sacl) yield return a.Sid;
    }

    private string? _sddl;
    public string Sddl => _sddl ??= BuildSddl();

    /// <summary>DACL part only ("D:PAI(...)"), as icacls /save writes it.</summary>
    public string DaclSddl => BuildSddl(daclOnly: true);

    public SdInfo(byte[] raw)
    {
        Raw = raw;
        try { Parse(raw); }
        catch (Exception ex) { ParseError = ex.Message; }
    }

    private void Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < 20) throw new InvalidDataException("Security descriptor too short");
        Control = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]);
        int oOwner = BinaryPrimitives.ReadInt32LittleEndian(b[4..]);
        int oGroup = BinaryPrimitives.ReadInt32LittleEndian(b[8..]);
        int oSacl = BinaryPrimitives.ReadInt32LittleEndian(b[12..]);
        int oDacl = BinaryPrimitives.ReadInt32LittleEndian(b[16..]);
        if (oOwner > 0) Owner = SidText.FromBinary(b[oOwner..], out _);
        if (oGroup > 0) Group = SidText.FromBinary(b[oGroup..], out _);
        if (DaclPresent && oDacl > 0) { DaclRevision = b[oDacl]; Dacl = ParseAcl(b[oDacl..]); }
        if (SaclPresent && oSacl > 0) Sacl = ParseAcl(b[oSacl..]);
    }

    private static List<AceInfo> ParseAcl(ReadOnlySpan<byte> b)
    {
        int aclSize = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
        var list = new List<AceInfo>(count);
        int pos = 8;
        for (int i = 0; i < count && pos + 4 <= aclSize && pos + 4 <= b.Length; i++)
        {
            byte type = b[pos];
            var flags = (AceFlags)b[pos + 1];
            int size = BinaryPrimitives.ReadUInt16LittleEndian(b[(pos + 2)..]);
            if (size < 8 || pos + size > b.Length) break;
            var ace = b.Slice(pos, size);
            uint mask = BinaryPrimitives.ReadUInt32LittleEndian(ace[4..]);
            int sidOffset = 8;
            Guid? objType = null, inhType = null;
            if (AceTypes.IsObject(type) && size >= 12)
            {
                uint oflags = BinaryPrimitives.ReadUInt32LittleEndian(ace[8..]);
                sidOffset = 12;
                if ((oflags & 1) != 0) { objType = new Guid(ace.Slice(sidOffset, 16)); sidOffset += 16; }
                if ((oflags & 2) != 0) { inhType = new Guid(ace.Slice(sidOffset, 16)); sidOffset += 16; }
            }
            string sid = "";
            int sidLen = 0;
            if (type != AceTypes.AccessAllowedCompound && sidOffset < size)
                sid = SidText.FromBinary(ace[sidOffset..], out sidLen);
            bool hasCond = AceTypes.IsCallback(type) && sidOffset + sidLen < size;
            list.Add(new AceInfo
            {
                Type = type, Flags = flags, Mask = mask, Sid = sid, HasCondition = hasCond,
                ObjectType = objType, InheritedObjectType = inhType, Index = i, Raw = ace.ToArray(),
            });
            pos += size;
        }
        return list;
    }

    // ---- SDDL -----------------------------------------------------------------------------------

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern unsafe bool ConvertSecurityDescriptorToStringSecurityDescriptorW(byte* sd, uint revision, uint info, out IntPtr str, out uint len);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr h);

    private unsafe string BuildSddl(bool daclOnly = false)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                fixed (byte* p = Raw)
                {
                    // OWNER|GROUP|DACL|SACL|LABEL|ATTRIBUTE|SCOPE
                    uint info = daclOnly ? 0x4u : 0x1F | 0x20 | 0x40;
                    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(p, 1, info, out var s, out _))
                    {
                        try { return Marshal.PtrToStringUni(s) ?? ""; }
                        finally { LocalFree(s); }
                    }
                }
            }
            catch { /* fall back */ }
        }
        return FallbackSddl(daclOnly);
    }

    private string FallbackSddl(bool daclOnly = false)
    {
        var sb = new StringBuilder();
        if (!daclOnly && Owner != null) sb.Append("O:").Append(Owner);
        if (!daclOnly && Group != null) sb.Append("G:").Append(Group);
        if (DaclPresent)
        {
            sb.Append("D:");
            if (DaclProtected) sb.Append('P');
            if (DaclAutoInherited) sb.Append("AI");
            if (Dacl == null) sb.Append("NO_ACCESS_CONTROL");
            else foreach (var a in Dacl) AppendAce(sb, a);
        }
        if (SaclPresent && !daclOnly)
        {
            sb.Append("S:");
            if (SaclProtected) sb.Append('P');
            if ((Control & SE_SACL_AUTO_INHERITED) != 0) sb.Append("AI");
            if (Sacl != null) foreach (var a in Sacl) AppendAce(sb, a);
        }
        return sb.ToString();
    }

    private static void AppendAce(StringBuilder sb, AceInfo a)
    {
        string t = a.Type switch
        {
            AceTypes.AccessAllowed => "A", AceTypes.AccessDenied => "D", AceTypes.SystemAudit => "AU",
            AceTypes.SystemMandatoryLabel => "ML", AceTypes.AccessAllowedCallback => "XA", AceTypes.AccessDeniedCallback => "XD",
            AceTypes.SystemResourceAttribute => "RA", AceTypes.SystemScopedPolicyId => "SP", AceTypes.SystemProcessTrustLabel => "TL",
            _ => $"0x{a.Type:X}",
        };
        var f = new StringBuilder();
        if ((a.Flags & AceFlags.ObjectInherit) != 0) f.Append("OI");
        if ((a.Flags & AceFlags.ContainerInherit) != 0) f.Append("CI");
        if ((a.Flags & AceFlags.NoPropagateInherit) != 0) f.Append("NP");
        if ((a.Flags & AceFlags.InheritOnly) != 0) f.Append("IO");
        if ((a.Flags & AceFlags.Inherited) != 0) f.Append("ID");
        if ((a.Flags & AceFlags.SuccessfulAccess) != 0) f.Append("SA");
        if ((a.Flags & AceFlags.FailedAccess) != 0) f.Append("FA");
        sb.Append('(').Append(t).Append(';').Append(f).Append(";0x").Append(a.Mask.ToString("x")).Append(";;;").Append(a.Sid).Append(')');
    }
}

public static class SidText
{
    public static string FromBinary(ReadOnlySpan<byte> b, out int length)
    {
        length = 0;
        if (b.Length < 8) return "";
        byte rev = b[0];
        int subCount = b[1];
        length = 8 + 4 * subCount;
        if (b.Length < length) { length = 0; return ""; }
        ulong auth = 0;
        for (int i = 2; i < 8; i++) auth = (auth << 8) | b[i];
        var sb = new StringBuilder("S-").Append(rev).Append('-');
        if (auth >= (1UL << 32)) sb.Append("0x").Append(auth.ToString("X12")); else sb.Append(auth);
        for (int i = 0; i < subCount; i++)
            sb.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(b[(8 + 4 * i)..]));
        return sb.ToString();
    }

    /// <summary>Binary form of a string SID (S-1-...). Returns null when the text is not a SID.</summary>
    public static byte[]? ToBinary(string sid)
    {
        var parts = sid.Split('-');
        if (parts.Length < 3 || parts[0] != "S" || !byte.TryParse(parts[1], out var rev)) return null;
        ulong auth;
        if (parts[2].StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        { if (!ulong.TryParse(parts[2][2..], System.Globalization.NumberStyles.HexNumber, null, out auth)) return null; }
        else if (!ulong.TryParse(parts[2], out auth)) return null;
        int sub = parts.Length - 3;
        if (sub > 15) return null;
        var b = new byte[8 + 4 * sub];
        b[0] = rev; b[1] = (byte)sub;
        for (int i = 0; i < 6; i++) b[7 - i] = (byte)(auth >> (8 * i));
        for (int i = 0; i < sub; i++)
        {
            if (!uint.TryParse(parts[3 + i], out var v)) return null;
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8 + 4 * i), v);
        }
        return b;
    }

    /// <summary>For S-1-5-21-a-b-c-RID returns ("S-1-5-21-a-b-c", RID); otherwise null.</summary>
    public static (string Prefix, uint Rid)? SplitAccountSid(string sid)
    {
        if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) return null;
        var parts = sid.Split('-');
        if (parts.Length != 8) return null;
        if (!uint.TryParse(parts[7], out var rid)) return null;
        return (string.Join('-', parts, 0, 7), rid);
    }
}
