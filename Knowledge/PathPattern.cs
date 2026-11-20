using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using AclLegibility.Model;

namespace AclLegibility.Knowledge;

/// <summary>
/// Path patterns with %Variables% taken from the scanned machine, "*" for one segment (or part of one)
/// and "**" for any number of segments. Matching is case-insensitive.
/// </summary>
public sealed class PathPattern
{
    private readonly string[] _segments;
    public string Source { get; }
    public int Specificity { get; }

    private PathPattern(string source, string[] segments)
    {
        Source = source;
        _segments = segments;
        int score = 0;
        foreach (var s in segments)
            score += s == "**" ? 0 : s.Contains('*') || s.Contains('?') ? 3 : 10;
        Specificity = score;
    }

    private static readonly Regex VarRx = new(@"%([^%]+)%", RegexOptions.Compiled);

    public static PathPattern? Create(string pattern, OsInfo os)
    {
        bool ok = true;
        var expanded = VarRx.Replace(pattern, m =>
        {
            if (os.Paths.TryGetValue(m.Groups[1].Value, out var v)) return v;
            ok = false;
            return m.Value;
        });
        if (!ok) return null;
        return new PathPattern(pattern, Split(expanded));
    }

    public static string[] Split(string path) =>
        path.Replace('/', '\\').TrimEnd('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);

    public bool IsMatch(string[] pathSegments) => Match(0, pathSegments, 0);

    /// <summary>The expanded segments ("*" and "**" kept as written).</summary>
    public IReadOnlyList<string> Segments => _segments;

    /// <summary>Expands a link target: %Variables% from the machine, {parent} = the folder holding the link,
    /// then resolves "." and "..". Null when a variable is unknown.</summary>
    public static string? ExpandTarget(string target, string parentPath, OsInfo os)
    {
        bool ok = true;
        var s = VarRx.Replace(target.Replace("{parent}", parentPath.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase), m =>
        {
            if (os.Paths.TryGetValue(m.Groups[1].Value, out var v)) return v;
            ok = false;
            return m.Value;
        });
        return ok ? Normalize(s) : null;
    }

    /// <summary>Backslashes, no trailing separator except on a drive root, "." and ".." resolved.</summary>
    public static string Normalize(string path)
    {
        var parts = new List<string>();
        foreach (var seg in Split(path))
        {
            if (seg == ".") continue;
            if (seg == "..") { if (parts.Count > 1) parts.RemoveAt(parts.Count - 1); continue; }
            parts.Add(seg);
        }
        if (parts.Count == 0) return path;
        return parts.Count == 1 && parts[0].EndsWith(':') ? parts[0] + "\\" : string.Join("\\", parts);
    }

    /// <summary>The expanded path when the pattern has no wildcards, else null.</summary>
    public string? LiteralPath =>
        _segments.Any(s => s.Contains('*') || s.Contains('?')) ? null
        : _segments.Length == 1 ? _segments[0] + "\\" : string.Join("\\", _segments);

    private bool Match(int pi, string[] path, int si)
    {
        while (true)
        {
            if (pi == _segments.Length) return si == path.Length;
            var seg = _segments[pi];
            if (seg == "**")
            {
                for (int k = si; k <= path.Length; k++)
                    if (Match(pi + 1, path, k)) return true;
                return false;
            }
            if (si == path.Length) return false;
            if (!Kb.Glob(seg, path[si])) return false;
            pi++; si++;
        }
    }
}

/// <summary>Knowledge entries pre-compiled against one machine's folder layout.</summary>
public sealed class CompiledKb
{
    public KnowledgeBase Kb { get; }
    public OsInfo Os { get; }

    public readonly List<(KbPath Entry, PathPattern Pattern, List<AceSpec>? Aces)> Paths = new();
    public readonly List<(KbPattern Entry, List<PathPattern>? Under)> Patterns = new();
    public readonly List<(KbQuirk Entry, List<PathPattern>? Under)> Quirks = new();
    public readonly List<(KbItem Entry, List<PathPattern> Paths, List<PathPattern>? Under)> Items = new();
    public readonly List<(KbStream Entry, List<PathPattern>? Under)> Streams = new();
    public readonly List<(KbReparsePoint Entry, PathPattern Pattern)> ReparsePoints = new();
    public readonly Dictionary<uint, KbReparseTag> ReparseTags = new();
    public readonly Dictionary<string, KbPrincipal> PrincipalsExact = new(StringComparer.OrdinalIgnoreCase);
    public readonly List<(KbPrincipal Entry, Regex Rx)> PrincipalPatterns = new();
    public readonly List<string> Problems = new();
    public readonly List<PathPattern> SystemAreas = new();

    public CompiledKb(KnowledgeBase kb, OsInfo os)
    {
        Kb = kb; Os = os;
        var d = kb.Doc;

        foreach (var p in d.Principals)
        {
            if (!string.IsNullOrEmpty(p.Sid)) PrincipalsExact.TryAdd(p.Sid, p);
            else if (!string.IsNullOrEmpty(p.SidPattern))
                PrincipalPatterns.Add((p, new Regex("^" + Regex.Escape(p.SidPattern).Replace(@"\*", "[0-9-]+") + "$", RegexOptions.Compiled)));
        }

        foreach (var e in d.Paths.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os)))
        {
            List<AceSpec>? aces = null;
            if (e.Aces != null)
            {
                aces = new();
                foreach (var a in e.Aces)
                {
                    var spec = AceSpec.Parse(a);
                    if (spec == null) Problems.Add($"{e.Id}: cannot read ACE \"{a}\"");
                    else aces.Add(spec);
                }
            }
            foreach (var v in e.Variants ?? new List<KbVariant>())
            {
                if (v.Aces == null) continue;
                v.Parsed = new();
                foreach (var a in v.Aces)
                {
                    var spec = AceSpec.Parse(a);
                    if (spec == null) Problems.Add($"{e.Id} (variant {v.Label}): cannot read ACE \"{a}\"");
                    else v.Parsed.Add(spec);
                }
            }
            foreach (var path in Many(e.Path, e.Paths))
            {
                var pp = PathPattern.Create(path, os);
                if (pp != null) Paths.Add((e, pp, aces));
            }
        }
        Paths.Sort((a, b) => b.Pattern.Specificity.CompareTo(a.Pattern.Specificity));

        foreach (var e in d.Patterns.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os))) Patterns.Add((e, Under(e.Under)));
        foreach (var e in d.Quirks.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os))) Quirks.Add((e, Under(e.Under)));
        foreach (var e in d.Streams.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os))) Streams.Add((e, Under(e.Under)));
        foreach (var e in d.ReparsePoints.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os)))
            foreach (var path in Many(e.Path, e.Paths))
            {
                var pp = PathPattern.Create(path, os);
                if (pp != null) ReparsePoints.Add((e, pp));
            }
        ReparsePoints.Sort((a, b) => b.Pattern.Specificity.CompareTo(a.Pattern.Specificity));
        foreach (var e in d.Items.Where(e => global::AclLegibility.Knowledge.Kb.OsMatches(e, os)))
        {
            var paths = Many(e.Path, e.Paths).Select(x => PathPattern.Create(x, os)).Where(x => x != null).Select(x => x!).ToList();
            Items.Add((e, paths, Under(e.Under)));
        }
        foreach (var area in d.SystemAreas ?? new List<string>())
        {
            var pp = PathPattern.Create(area.TrimEnd('\\') + @"\**", os);
            if (pp != null) SystemAreas.Add(pp);
        }
        foreach (var t in d.ReparseTags)
        {
            var s = t.Tag.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? t.Tag[2..] : t.Tag;
            if (uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var tag)) ReparseTags.TryAdd(tag, t);
            else Problems.Add($"{t.Id}: bad reparse tag {t.Tag}");
        }
    }

    private static IEnumerable<string> Many(string? one, List<string>? many)
    {
        if (!string.IsNullOrEmpty(one)) yield return one;
        if (many != null) foreach (var m in many) yield return m;
    }

    private List<PathPattern>? Under(List<string>? under)
    {
        if (under == null || under.Count == 0) return null;
        var list = new List<PathPattern>();
        foreach (var u in under)
        {
            var pp = PathPattern.Create(u.TrimEnd('\\') + @"\**", Os);
            if (pp != null) list.Add(pp);
        }
        return list;
    }

    /// <summary>"What it is" entries for this object: path matches first, then name matches.</summary>
    public IEnumerable<KbItem> ItemsFor(ScanNode n)
    {
        var segs = PathPattern.Split(n.FullPath);
        foreach (var (e, paths, _) in Items) if (paths.Any(p => p.IsMatch(segs))) yield return e;
        foreach (var (e, paths, under) in Items)
            if (paths.Count == 0 && e.Name != null && global::AclLegibility.Knowledge.Kb.Glob(e.Name, n.Name) && UnderMatches(under, segs)) yield return e;
    }

    public static bool UnderMatches(List<PathPattern>? under, string[] segs) =>
        under == null || under.Any(u => u.IsMatch(segs));

    /// <summary>Specificity of the best "under" match (0 when the rule has no restriction).</summary>
    public static int UnderScore(List<PathPattern>? under, string[] segs) =>
        under == null ? 0 : under.Where(u => u.IsMatch(segs)).Select(u => u.Specificity).DefaultIfEmpty(-1).Max();

    public bool InSystemArea(string[] segs) => SystemAreas.Any(a => a.IsMatch(segs));

    public KbPrincipal? Principal(string sid)
    {
        if (PrincipalsExact.TryGetValue(sid, out var p)) return p;
        foreach (var (e, rx) in PrincipalPatterns) if (rx.IsMatch(sid)) return e;
        return null;
    }

    public KbReparseTag? Tag(uint tag)
    {
        if (ReparseTags.TryGetValue(tag, out var t)) return t;
        // cloud files use 0x9000x01A variants
        if ((tag & 0xFFFF0FFF) == 0x9000001A && ReparseTags.TryGetValue(0x9000001A, out t)) return t;
        return null;
    }
}
