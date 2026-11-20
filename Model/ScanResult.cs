using System;
using System.Collections.Generic;
using System.Linq;
using AclLegibility.Security;

namespace AclLegibility.Model;

public sealed class ScanResult
{
    public OsInfo Os { get; set; } = new();
    public DateTime ScannedUtc { get; set; } = DateTime.UtcNow;
    public List<ScanNode> Roots { get; } = new();
    public SdTable Descriptors { get; } = new();
    public Dictionary<string, PrincipalName> Names { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Inventory Inventory { get; set; } = new();
    public List<string> PrivilegesEnabled { get; set; } = new();
    public long ObjectCount { get; set; }
    public long ErrorCount { get; set; }
    /// <summary>The scan was cancelled: the tree is partial, so absences prove nothing.</summary>
    public bool Cancelled { get; set; }
    public TimeSpan Duration { get; set; }

    /// <summary>True when this result was scanned on the running machine in this session
    /// (live reads such as stream contents are possible). False for loaded snapshots.</summary>
    public bool IsLive { get; set; }
    public string? SourceFile { get; set; }
    /// <summary>Something the user should know about a loaded snapshot (e.g. data an older version recorded wrongly).</summary>
    public string? LoadNote { get; set; }

    // Filled by the classifier
    public List<Finding> Findings { get; set; } = new();
    /// <summary>Objects and links a standard install of this Windows creates that are not in this scan. Listed apart,
    /// never judged: an image built with fewer components (or a clean-up) leaves them out on purpose.</summary>
    public List<NotPresentItem> NotPresent { get; set; } = new();
    /// <summary>Folders whose contents could not be listed: nothing below them is reported as not present.</summary>
    public List<string> NotPresentUnlisted { get; set; } = new();
    public SdInfo?[] SdInfos { get; set; } = Array.Empty<SdInfo?>();

    public SdInfo? SdOf(ScanNode n) => n.SdIndex >= 0 && n.SdIndex < SdInfos.Length ? SdInfos[n.SdIndex] : null;

    public PrincipalName NameOf(string sid) =>
        Names.TryGetValue(sid, out var p) ? p : new PrincipalName { Sid = sid, Use = SidUse.Unresolved };

    public IEnumerable<ScanNode> AllNodes()
    {
        var stack = new Stack<ScanNode>();
        for (int i = Roots.Count - 1; i >= 0; i--) stack.Push(Roots[i]);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            yield return n;
            if (n.Children != null)
                for (int i = n.Children.Count - 1; i >= 0; i--) stack.Push(n.Children[i]);
        }
    }

    public ScanNode? FindByPath(string path)
    {
        foreach (var root in Roots)
        {
            if (!path.StartsWith(root.Name.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) continue;
            var rest = path.Length > root.Name.TrimEnd('\\').Length ? path[root.Name.TrimEnd('\\').Length..].Trim('\\') : "";
            var node = root;
            if (rest.Length == 0) return node;
            foreach (var part in rest.Split('\\'))
            {
                var next = node.Children?.FirstOrDefault(c => string.Equals(c.Name, part, StringComparison.OrdinalIgnoreCase));
                if (next == null) { node = null!; break; }
                node = next;
            }
            if (node != null) return node;
        }
        return null;
    }
}

/// <summary>A stock object or compatibility link that is not in the scan (see <see cref="ScanResult.NotPresent"/>).</summary>
public sealed class NotPresentItem
{
    public required string Path { get; init; }
    /// <summary>The folder that would hold it.</summary>
    public required string Folder { get; init; }
    public bool IsLink { get; init; }
    /// <summary>For a link: where Windows points it.</summary>
    public string? Target { get; init; }
    public required string KbId { get; init; }
    public string? Explain { get; init; }
}
