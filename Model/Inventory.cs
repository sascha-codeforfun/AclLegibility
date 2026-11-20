using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
namespace AclLegibility.Model;

/// <summary>SID_NAME_USE</summary>
public enum SidUse { Unknown = 0, User = 1, Group = 2, Domain = 3, Alias = 4, WellKnownGroup = 5, DeletedAccount = 6, Invalid = 7, Unresolved = 8, Computer = 9, Label = 10, LogonSession = 11 }

public sealed class PrincipalName
{
    public string Sid { get; set; } = "";
    public string? Domain { get; set; }
    public string? Name { get; set; }
    public SidUse Use { get; set; }
    /// <summary>Win32 error of the failed lookup (0 = resolved or not recorded). 1332 = none mapped:
    /// Windows asked every authority it knows and none knows the SID.</summary>
    public int LookupError { get; set; }

    public bool Resolved => !string.IsNullOrEmpty(Name);
    public string Display => !Resolved ? Sid : string.IsNullOrEmpty(Domain) ? Name! : $"{Domain}\\{Name}";
}

public sealed class LocalUser
{
    public string Name { get; set; } = "";
    public string? Sid { get; set; }
    public string? Comment { get; set; }
    public uint Flags { get; set; }
    public bool Disabled => (Flags & 0x2) != 0;
}

public sealed class GroupMember
{
    public string Sid { get; set; } = "";
    public string Name { get; set; } = "";
    public SidUse Use { get; set; }
}

public sealed class LocalGroup
{
    public string Name { get; set; } = "";
    public string? Sid { get; set; }
    public string? Comment { get; set; }
    public List<GroupMember> Members { get; set; } = new();
}

public sealed class ShareEntry
{
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public uint Type { get; set; }
    public string? Remark { get; set; }
    public byte[]? SecurityDescriptor { get; set; }

    public string TypeText
    {
        get
        {
            var special = (Type & 0x80000000) != 0 ? " (special)" : "";
            var tmp = (Type & 0x40000000) != 0 ? " (temporary)" : "";
            var baseType = (Type & 0xFF) switch { 0 => "Disk", 1 => "Print queue", 2 => "Device", 3 => "IPC", _ => $"Type {Type & 0xFF}" };
            return baseType + special + tmp;
        }
    }
}

public sealed class Inventory
{
    public List<LocalUser> Users { get; set; } = new();
    public List<LocalGroup> Groups { get; set; } = new();
    public List<ShareEntry> Shares { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    /// <summary>Account SIDs Windows keeps records of outside the account database, with where (live scans only, not
    /// kept in snapshots): User Manager's records (HKLM\SOFTWARE\Microsoft\UserManager\Users) and the app store's
    /// per-account keys (…\Appx\AppxAllUserStore\&lt;SID&gt;). For a deleted account these are lingering traces.</summary>
    public Dictionary<string, List<string>> AccountTraces { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Local groups the SID is a direct member of.</summary>
    public IEnumerable<LocalGroup> GroupsOf(string sid) =>
        Groups.Where(g => g.Members.Any(m => string.Equals(m.Sid, sid, StringComparison.OrdinalIgnoreCase)));
}
