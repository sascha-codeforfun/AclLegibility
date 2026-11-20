using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AclLegibility.Model;
using AclLegibility.Security;

namespace AclLegibility.Knowledge;

// ---- JSON model -------------------------------------------------------------------------------

public class KbEntry
{
    public string Id { get; set; } = "";
    /// <summary>win10, win11, srv2019, srv2025 (others are accepted). Null = all.</summary>
    public List<string>? Os { get; set; }
    public string? Confidence { get; set; }
    public string? Explain { get; set; }
    public string? Origin { get; set; }
    /// <summary>In knowledge.user.json: removes the built-in entry with the same id.</summary>
    public bool Remove { get; set; }

    [JsonIgnore] public Confidence ConfidenceValue => Kb.ParseConfidence(Confidence);
    [JsonIgnore] public Origin OriginValue => Kb.ParseOrigin(Origin, Model.Origin.Stock);
    [JsonIgnore] public bool FromUserFile { get; set; }
}

public sealed class KbPrincipal : KbEntry
{
    public string? Sid { get; set; }
    public string? SidPattern { get; set; }
    public string? Name { get; set; }
    /// <summary>True for principals that exist on every Windows installation.</summary>
    public bool Builtin { get; set; } = true;
}

public sealed class KbPath : KbEntry
{
    public string? Path { get; set; }
    public List<string>? Paths { get; set; }
    public string? Owner { get; set; }
    public bool? Protected { get; set; }
    /// <summary>"exact" (default): explicit ACEs must equal the list. "contains": listed ACEs must be present, others allowed.</summary>
    public string? Mode { get; set; }
    /// <summary>"type;flags;rights;principal[;options]" e.g. "A;OICI;F;BA". Null = location known but ACL not compared.</summary>
    public List<string>? Aces { get; set; }
    /// <summary>Windows creates this object; its absence (in a complete scan of its volume) is reported.</summary>
    public bool Expected { get; set; }
    /// <summary>"dir" or "file": the entry applies only to objects of that kind (e.g. profile folders, not desktop.ini).</summary>
    public string? Kind { get; set; }
    /// <summary>Other ACLs Windows is known to write here (another build, an upgraded install). A match counts as stock.</summary>
    public List<KbVariant>? Variants { get; set; }
}

/// <summary>A known alternative ACL for a path entry. Unset owner/protected/mode fall back to the entry's.</summary>
public sealed class KbVariant
{
    public string Label { get; set; } = "";
    public string? Owner { get; set; }
    public bool? Protected { get; set; }
    public string? Mode { get; set; }
    public List<string>? Aces { get; set; }
    public string? Explain { get; set; }
    [JsonIgnore] public List<AceSpec>? Parsed { get; set; }
}

public sealed class KbPattern : KbEntry
{
    public List<string>? Under { get; set; }
    public List<string>? Owners { get; set; }
    /// <summary>Every explicit ACE principal must match one of these (aliases or SID globs).</summary>
    public List<string>? Principals { get; set; }
    public bool? Protected { get; set; }
    /// <summary>Only with an explanation of why: objects matched by this rule may be deleted by the orphan clean-up,
    /// also inside %SystemRoot% (listed separately there, never ticked by default).</summary>
    public bool Removable { get; set; }
}

public sealed class KbQuirk : KbEntry
{
    public string Category { get; set; } = "";
    public List<string>? Under { get; set; }
}

public sealed class KbStream : KbEntry
{
    public string Name { get; set; } = "";
    public List<string>? Under { get; set; }
}

public sealed class KbReparseTag : KbEntry
{
    public string Tag { get; set; } = "";
    public string? Name { get; set; }
}

public sealed class KbReparsePoint : KbEntry
{
    public string? Path { get; set; }
    public List<string>? Paths { get; set; }
    public string? Tag { get; set; }
    /// <summary>Where the link must point. %Variables% as in paths; {parent} = the folder that holds the link; ".." allowed.
    /// A different target makes the link Modified.</summary>
    public string? Target { get; set; }
    /// <summary>Windows creates this link; its absence (in a complete scan of its volume) is reported, quietly.</summary>
    public bool Expected { get; set; }
}

public sealed class KbShare : KbEntry
{
    public string Name { get; set; } = "";
}

public sealed class KbAccount : KbEntry
{
    public string? Name { get; set; }
    public int? Rid { get; set; }
}

/// <summary>What a file or folder is, shown in its details ("What it is"). Explanation only: it changes no
/// classification. Matched by path (patterns) or by name (glob), optionally restricted to "under".</summary>
public sealed class KbItem : KbEntry
{
    public string? Path { get; set; }
    public List<string>? Paths { get; set; }
    public string? Name { get; set; }
    public List<string>? Under { get; set; }
    /// <summary>A short "how to change it" text, shown copyable (registry values, commands).</summary>
    public string? How { get; set; }
    /// <summary>Steps that can be taken back (switch off, disable — with the line that restores it).</summary>
    public string? HowReversible { get; set; }
    /// <summary>Steps that cannot be taken back (delete, remove for good).</summary>
    public string? HowFinal { get; set; }
    /// <summary>Show the first few KB of the file's text (desktop.ini and similar).</summary>
    public bool ShowText { get; set; }
}

public sealed class KbDocument
{
    public int Version { get; set; }
    public string? Description { get; set; }
    public List<KbPrincipal> Principals { get; set; } = new();
    public List<KbPath> Paths { get; set; } = new();
    public List<KbPattern> Patterns { get; set; } = new();
    public List<KbQuirk> Quirks { get; set; } = new();
    public List<KbStream> Streams { get; set; } = new();
    public List<KbReparseTag> ReparseTags { get; set; } = new();
    public List<KbReparsePoint> ReparsePoints { get; set; } = new();
    public List<KbShare> Shares { get; set; } = new();
    public List<KbAccount> Accounts { get; set; } = new();
    public List<KbItem> Items { get; set; } = new();
    /// <summary>Where Windows itself sets explicit permissions. Outside these, explicit entries
    /// for built-in principals are Custom. A list in knowledge.user.json replaces this one.</summary>
    public List<string>? SystemAreas { get; set; }
}

// ---- Loading / merging -----------------------------------------------------------------------

public sealed class KnowledgeBase
{
    public KbDocument Doc { get; }
    public int UserEntryCount { get; }
    public List<string> LoadMessages { get; } = new();
    public string? UserFilePath { get; }

    public int EntryCount =>
        Doc.Principals.Count + Doc.Paths.Count + Doc.Patterns.Count + Doc.Quirks.Count + Doc.Streams.Count +
        Doc.ReparseTags.Count + Doc.ReparsePoints.Count + Doc.Shares.Count + Doc.Accounts.Count + Doc.Items.Count;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private KnowledgeBase(KbDocument doc, int userCount, string? userPath, List<string> messages)
    {
        Doc = doc; UserEntryCount = userCount; UserFilePath = userPath; LoadMessages = messages;
    }

    public static KnowledgeBase Load(string? builtinJson = null, string? userFilePath = null)
    {
        var messages = new List<string>();
        builtinJson ??= ReadEmbedded();
        var doc = JsonSerializer.Deserialize<KbDocument>(builtinJson, JsonOptions) ?? new KbDocument();
        int userCount = 0;
        if (userFilePath != null && File.Exists(userFilePath))
        {
            try
            {
                var user = JsonSerializer.Deserialize<KbDocument>(File.ReadAllText(userFilePath), JsonOptions);
                if (user != null) userCount = Merge(doc, user);
                messages.Add($"Loaded {userCount} entries from {System.IO.Path.GetFileName(userFilePath)}.");
            }
            catch (Exception ex)
            {
                messages.Add($"Could not read {System.IO.Path.GetFileName(userFilePath)}: {ex.Message}");
            }
        }
        return new KnowledgeBase(doc, userCount, userFilePath, messages);
    }

    private static string ReadEmbedded()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var s = asm.GetManifestResourceStream("AclLegibility.knowledge.json")
                      ?? throw new InvalidOperationException("Embedded knowledge base missing");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    private static int Merge(KbDocument target, KbDocument user)
    {
        int n = 0;
        n += MergeList(target.Principals, user.Principals);
        n += MergeList(target.Paths, user.Paths);
        n += MergeList(target.Patterns, user.Patterns);
        n += MergeList(target.Quirks, user.Quirks);
        n += MergeList(target.Streams, user.Streams);
        n += MergeList(target.ReparseTags, user.ReparseTags);
        n += MergeList(target.ReparsePoints, user.ReparsePoints);
        n += MergeList(target.Shares, user.Shares);
        n += MergeList(target.Accounts, user.Accounts);
        n += MergeList(target.Items, user.Items);
        if (user.SystemAreas != null) { target.SystemAreas = user.SystemAreas; n++; }
        return n;
    }

    private static int MergeList<T>(List<T> target, List<T>? user) where T : KbEntry
    {
        if (user == null) return 0;
        foreach (var e in user)
        {
            e.FromUserFile = true;
            int i = string.IsNullOrEmpty(e.Id) ? -1 : target.FindIndex(t => string.Equals(t.Id, e.Id, StringComparison.OrdinalIgnoreCase));
            if (e.Remove) { if (i >= 0) target.RemoveAt(i); continue; }
            // user entries go first so they win ties in first-match lookups
            if (i >= 0) target.RemoveAt(i);
            target.Insert(0, e);
        }
        return user.Count;
    }
}

// ---- Shared helpers ------------------------------------------------------------------------

public static class Kb
{
    public static Confidence ParseConfidence(string? s) => s?.ToLowerInvariant() switch
    {
        "documented" => Model.Confidence.Documented,
        "observed" => Model.Confidence.Observed,
        "assumed" => Model.Confidence.Assumed,
        "unverified" => Model.Confidence.Unverified,
        _ => Model.Confidence.Assumed,
    };

    public static Origin ParseOrigin(string? s, Origin fallback) => s?.ToLowerInvariant() switch
    {
        "stock" => Origin.Stock,
        "custom" => Origin.Custom,
        "unknown" => Origin.Unknown,
        "modified" => Origin.Modified,
        "trace" => Origin.Trace,
        "peraccount" or "stock-per-account" => Origin.PerAccount,
        _ => fallback,
    };

    public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// <summary>Principal aliases usable in knowledge entries (SDDL-style plus a few extras).</summary>
    public static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["WD"] = "S-1-1-0", ["EVERYONE"] = "S-1-1-0",
        ["CO"] = "S-1-3-0", ["CG"] = "S-1-3-1", ["OW"] = "S-1-3-4",
        ["NU"] = "S-1-5-2", ["BATCH"] = "S-1-5-3", ["IU"] = "S-1-5-4", ["SU"] = "S-1-5-6", ["AN"] = "S-1-5-7",
        ["AU"] = "S-1-5-11", ["RC"] = "S-1-5-12", ["IUSR"] = "S-1-5-17",
        ["SY"] = "S-1-5-18", ["LS"] = "S-1-5-19", ["NS"] = "S-1-5-20",
        ["BA"] = "S-1-5-32-544", ["BU"] = "S-1-5-32-545", ["BG"] = "S-1-5-32-546", ["PU"] = "S-1-5-32-547",
        ["BO"] = "S-1-5-32-551", ["RD"] = "S-1-5-32-555", ["IIS_IUSRS"] = "S-1-5-32-568",
        ["AC"] = "S-1-15-2-1", ["RAC"] = "S-1-15-2-2",
        ["TI"] = TrustedInstaller,
        ["LA"] = "S-1-5-113",
    };

    public static string ResolveAlias(string token) => Aliases.TryGetValue(token.Trim(), out var sid) ? sid : token.Trim();

    private static readonly Dictionary<string, Regex> GlobCache = new();

    /// <summary>Case-insensitive glob (* and ?) match on a whole string.</summary>
    public static bool Glob(string pattern, string text)
    {
        if (!pattern.Contains('*') && !pattern.Contains('?')) return string.Equals(pattern, text, StringComparison.OrdinalIgnoreCase);
        Regex? rx;
        lock (GlobCache)
        {
            if (!GlobCache.TryGetValue(pattern, out rx))
            {
                rx = new Regex("^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
                GlobCache[pattern] = rx;
            }
        }
        return rx.IsMatch(text);
    }

    public static bool OsMatches(KbEntry e, OsInfo os) =>
        e.Os == null || e.Os.Count == 0 || e.Os.Any(o => string.Equals(o, os.FamilyKey, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Expected ACE parsed from "type;flags;rights;principal[;options]".</summary>
public sealed class AceSpec
{
    public bool Deny;
    public bool Audit;
    public AceFlags Inherit;
    public uint Mask;
    public string Principal = "";   // SID, "$OWNER", "$PROFILE", "$LOCALADMIN" or "cap:<capability name>"
    public bool Includes;           // actual mask may have more bits
    public bool Optional;
    public string Source = "";

    public static AceSpec? Parse(string s)
    {
        var f = s.Split(';');
        if (f.Length < 4) return null;
        var spec = new AceSpec { Source = s };
        switch (f[0].Trim().ToUpperInvariant())
        {
            case "A": break;
            case "D": spec.Deny = true; break;
            case "AU": spec.Audit = true; break;
            default: return null;
        }
        var flags = f[1].Trim().ToUpperInvariant();
        for (int i = 0; i + 2 <= flags.Length; i += 2)
        {
            var t = flags.Substring(i, 2);
            spec.Inherit |= t switch
            {
                "OI" => AceFlags.ObjectInherit, "CI" => AceFlags.ContainerInherit,
                "IO" => AceFlags.InheritOnly, "NP" => AceFlags.NoPropagateInherit,
                "SA" => AceFlags.SuccessfulAccess, "FA" => AceFlags.FailedAccess,
                _ => AceFlags.None,
            };
        }
        var m = Rights.Parse(f[2]);
        if (m == null) return null;
        spec.Mask = Rights.Normalize(m.Value);
        var p = f[3].Trim();
        spec.Principal = p.Equals("$OWNER", StringComparison.OrdinalIgnoreCase) ? "$OWNER"
            : p.Equals("$PROFILE", StringComparison.OrdinalIgnoreCase) ? "$PROFILE"
            : p.Equals("$LOCALADMIN", StringComparison.OrdinalIgnoreCase) ? "$LOCALADMIN"
            : p.StartsWith("cap:", StringComparison.OrdinalIgnoreCase) ? "cap:" + p[4..]
            : Kb.ResolveAlias(p);
        if (f.Length > 4)
            foreach (var opt in f[4].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (opt.Equals("includes", StringComparison.OrdinalIgnoreCase)) spec.Includes = true;
                if (opt.Equals("optional", StringComparison.OrdinalIgnoreCase)) spec.Optional = true;
            }
        return spec;
    }

    /// <summary>True when the principal is not a fixed SID but resolved per object ($OWNER, $PROFILE, cap:…).</summary>
    public bool IsSymbolic => Principal.StartsWith('$') || Principal.StartsWith("cap:", StringComparison.OrdinalIgnoreCase);

    /// <param name="sid">The SID the principal stands for on this object (resolved by the caller for symbolic principals).</param>
    public bool Matches(AceInfo a, string? sid)
    {
        if (Audit != a.IsAudit) return false;
        if (!Audit && Deny != a.IsDeny) return false;
        if (!string.Equals(sid, a.Sid, StringComparison.OrdinalIgnoreCase)) return false;
        var mask = (AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit | AceFlags.SuccessfulAccess | AceFlags.FailedAccess);
        if ((a.Flags & mask) != (Inherit & mask)) return false;
        var am = a.NormalizedMask;
        return Includes ? (am & Mask) == Mask : am == Mask;
    }
}
