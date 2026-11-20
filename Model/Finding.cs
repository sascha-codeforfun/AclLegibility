using System;
using System.Collections.Generic;
using System.IO;
namespace AclLegibility.Model;

/// <summary>
/// Where something comes from. Ordered by how much attention it deserves (higher = more).
/// Stock = shipped or set by Windows setup/servicing. Trace = a leftover of normal use
/// (download marks, object IDs, link-tracking, sync metadata) — real, but not configuration.
/// Unknown = cannot be told apart yet. Custom = the result of admin, user or application
/// activity. Modified = a known Windows object that differs from the knowledge base in a way that gives someone more
/// control. Differs = a known Windows object that differs from the reference install only in read/list rights or in
/// which system account (SYSTEM, Administrators, TrustedInstaller) holds a right — typically written by another build.
/// PerAccount = Windows' own per-account layout naming a real account (a profile, a policy record, a task of that account).
/// </summary>
public enum Origin { None = 0, Stock = 1, PerAccount = 2, Trace = 3, Differs = 4, Unknown = 5, Custom = 6, Modified = 7 }

public enum Confidence { None = 0, Documented, Observed, Assumed, Unverified }

public enum FindingCategory
{
    Acl,
    Stream,
    Reparse,
    Link,
    HardLink,
    CaseSensitive,
    Encrypted,
    Compressed,
    Sparse,
    ObjectId,
    LongPath,
    Unreadable,
    Orphan,
    /// <summary>Full control for one user account, added by Explorer's "Continue" (or set by hand the same way).</summary>
    ExplorerGrant,
    /// <summary>A package folder (Name_Version_Arch_Resource_PublisherId) with a newer version of the same package next to it.</summary>
    Superseded,
}

public sealed class Finding
{
    public required ScanNode Node { get; init; }
    public required FindingCategory Category { get; init; }
    public Origin Origin { get; set; }
    public string Summary { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string? KbId { get; set; }
    public Confidence Confidence { get; set; }
    public List<string>? Differences { get; set; }
    public bool UntestedOs { get; set; }
    /// <summary>An explicit Deny for Everyone, Authenticated Users, Users, SYSTEM or Administrators, outside the places the
    /// knowledge base knows. Drawn in the error colour.</summary>
    public bool BroadDeny { get; set; }
    /// <summary>A sub-kind shown next to the category, e.g. "in use" for Unreadable, "unverifiable" for Orphan.</summary>
    public string? Detail { get; set; }
    /// <summary>For Unreadable: the grouped cause (used by the cause filter).</summary>
    public ReadCause? Cause { get; set; }
    /// <summary>Objects below with the same explicit entries, folded into this finding.</summary>
    public int Folded { get; set; }

    /// <summary>For Explorer grants, Detail holds the account SID (for the undo button), not a kind detail.</summary>
    public string KindText => OriginText.Label(Category) + (Detail != null && Category != FindingCategory.ExplorerGrant ? " · " + Detail : "")
                              + (BroadDeny ? " · broad Deny" : "");

    public bool NeedsAttention => Origin is Origin.Unknown or Origin.Custom or Origin.Modified;
}

public static class OriginText
{
    public static string Label(Origin o) => o switch
    {
        Origin.Stock => "Stock",
        Origin.PerAccount => "Stock, per account",
        Origin.Modified => "Stock, modified",
        Origin.Differs => "Stock, differs",
        Origin.Custom => "Custom",
        Origin.Unknown => "Unknown",
        Origin.Trace => "Trace",
        _ => "",
    };

    public static string Label(Confidence c) => c switch
    {
        Confidence.Documented => "documented",
        Confidence.Observed => "observed",
        Confidence.Assumed => "assumed",
        Confidence.Unverified => "unverified",
        _ => "",
    };

    public static string Label(FindingCategory c) => c switch
    {
        FindingCategory.Acl => "Permissions",
        FindingCategory.Stream => "Alternate stream",
        FindingCategory.Reparse => "Reparse point",
        FindingCategory.Link => "Link",
        FindingCategory.HardLink => "Hard link",
        FindingCategory.CaseSensitive => "Case-sensitive dir",
        FindingCategory.Encrypted => "EFS encrypted",
        FindingCategory.Compressed => "Compressed",
        FindingCategory.Sparse => "Sparse",
        FindingCategory.ObjectId => "Object ID",
        FindingCategory.LongPath => "Long path",
        FindingCategory.Unreadable => "Unreadable",
        FindingCategory.Orphan => "Orphaned SID",
        FindingCategory.ExplorerGrant => "Explorer grant",
        FindingCategory.Superseded => "Superseded version",
        _ => c.ToString(),
    };
}

public enum OrphanState { None, Proven, Unverifiable }
