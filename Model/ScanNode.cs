using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AclLegibility.Model;

[Flags]
public enum NodeFlags : uint
{
    None = 0,
    Directory = 1 << 0,
    CaseSensitive = 1 << 1,
    SdIncludesSacl = 1 << 2,      // the SACL could be read (SeSecurityPrivilege)
    Unreadable = 1 << 3,          // security descriptor or metadata could not be read
    ListFailed = 1 << 4,          // directory contents could not be enumerated
    NotFollowed = 1 << 5,         // directory is a name-surrogate reparse point; not descended into
    IsVolumeRoot = 1 << 6,
}

public sealed class StreamEntry
{
    public string Name { get; init; } = "";
    public long Size { get; init; }
}

public sealed class ReparseInfo
{
    public uint Tag { get; init; }
    public string? SubstituteName { get; init; }
    public string? PrintName { get; init; }
    public string? Extra { get; init; }   // e.g. AppExecLink package / target exe

    public bool IsNameSurrogate => (Tag & 0x20000000) != 0;

    /// <summary>The target as a user would read it.</summary>
    public string? Target => !string.IsNullOrEmpty(PrintName) ? PrintName : CleanSubstitute(SubstituteName);

    private static string? CleanSubstitute(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        if (s.StartsWith(@"\??\UNC\", StringComparison.Ordinal)) return @"\\" + s[8..];
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) return s[4..];
        return s;
    }
}

/// <summary>Rarely needed data kept off the hot node object to save memory.</summary>
public sealed class NodeExtra
{
    public List<StreamEntry>? Streams;
    public ReparseInfo? Reparse;
    public int ErrorCode;
    public string? ErrorStage;
    public Guid? ObjectId;
}

/// <summary>One file system object. Memory-lean: whole volumes are held in memory.</summary>
public sealed class ScanNode
{
    public ScanNode? Parent;
    public string Name = "";          // for a root: the full root path ("C:\")
    public uint Attributes;
    public int SdIndex = -1;
    public NodeFlags Flags;
    public uint LinkCount;
    public long Size;
    /// <summary>Creation time as a FILETIME (UTC) from the directory listing; 0 when not known (roots, old snapshots).</summary>
    public long Created;
    public string? ShortName;
    public NodeExtra? Extra;
    public List<ScanNode>? Children;

    // Filled by the classifier
    public List<Finding>? Findings;
    public int SubtreeAttention;      // non-stock findings in this node and below
    public Origin SubtreeWorst = Origin.None;
    public int SubtreeModified;       // objects here and below whose worst finding is Modified
    public Origin SubtreeWorstRest = Origin.None;   // worst origin below among objects that are not Modified
    public int SubtreeLinks;          // junctions and symbolic links here and below (any origin)

    /// <summary>A directory junction or a symbolic link (not app aliases, cloud placeholders or dedup).</summary>
    public bool IsLink => Extra?.Reparse is { } rp && (rp.Tag == 0xA0000003 || rp.Tag == 0xA000000C);

    public bool IsDirectory => (Flags & NodeFlags.Directory) != 0;
    public bool IsRoot => Parent == null;

    public NodeExtra EnsureExtra() => Extra ??= new NodeExtra();

    public string FullPath
    {
        get
        {
            if (Parent == null) return Name;
            var parts = new Stack<string>();
            var n = this;
            while (n.Parent != null) { parts.Push(n.Name); n = n.Parent; }
            var sb = new StringBuilder(n.Name);
            foreach (var p in parts)
            {
                if (sb.Length > 0 && sb[^1] != '\\') sb.Append('\\');
                sb.Append(p);
            }
            return sb.ToString();
        }
    }

    public int Depth
    {
        get { int d = 0; for (var n = Parent; n != null; n = n.Parent) d++; return d; }
    }

    public IEnumerable<ScanNode> Ancestors()
    {
        for (var n = Parent; n != null; n = n.Parent) yield return n;
    }

    public override string ToString() => FullPath;
}
