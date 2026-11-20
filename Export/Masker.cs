using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Security;
using AclLegibility.Settings;

namespace AclLegibility.Export;

/// <summary>
/// Replaces identifying names with stable placeholders for sharing. Well-known principals stay readable;
/// accounts listed in settings (default: User, ElevatedUser) are shown by name only, without SID.
/// </summary>
public sealed class Masker
{
    private readonly ScanResult _r;
    private readonly CompiledKb _kb;
    public bool Enabled { get; }
    private readonly HashSet<string> _exempt;
    private readonly Dictionary<string, string> _accountPlaceholder = new(StringComparer.OrdinalIgnoreCase); // sid → <USERn>
    private readonly List<(Regex Rx, string Replacement)> _text = new();
    /// <summary>Names masked only as a whole path segment (profile folder names, account names shorter than 3 characters).</summary>
    private readonly List<(Regex Rx, string Replacement)> _segments = new();
    private readonly List<(string Prefix, string Replacement)> _sidPrefixes = new();

    public IReadOnlyCollection<string> ExemptNames => _exempt;

    public Masker(ScanResult r, CompiledKb kb, AppSettings settings, bool enabled)
    {
        _r = r; _kb = kb; Enabled = enabled;
        _exempt = new HashSet<string>(settings.UnmaskedAccounts ?? new(), StringComparer.OrdinalIgnoreCase);
        if (!enabled) return;

        // SID authority prefixes
        if (r.Os.MachineSid != null) _sidPrefixes.Add((r.Os.MachineSid, "S-1-5-21-<MACHINE>"));
        int d = 0;
        foreach (var prefix in r.Names.Keys.Select(SidText.SplitAccountSid).Where(x => x != null).Select(x => x!.Value.Prefix)
                     .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.Ordinal))
        {
            if (string.Equals(prefix, r.Os.MachineSid, StringComparison.OrdinalIgnoreCase)) continue;
            _sidPrefixes.Add((prefix, $"S-1-5-21-<DOMAIN{++d}>"));
        }

        // accounts with RID >= 1000 that are not exempt, numbered by SID for stable placeholders
        int u = 0, g = 0;
        var accounts = r.Names.Values
            .Where(p => SidText.SplitAccountSid(p.Sid) is { Rid: >= 1000 })
            .OrderBy(p => p.Use is SidUse.Group or SidUse.Alias or SidUse.WellKnownGroup ? 1 : 0)
            .ThenBy(p => p.Sid, StringComparer.Ordinal);
        var names = new List<(string Name, string Placeholder)>();
        foreach (var p in accounts)
        {
            if (p.Name != null && _exempt.Contains(p.Name)) continue;
            bool isGroup = p.Use is SidUse.Group or SidUse.Alias or SidUse.WellKnownGroup;
            var ph = isGroup ? $"<GROUP{++g}>" : $"<USER{++u}>";
            _accountPlaceholder[p.Sid] = ph;
            if (!string.IsNullOrEmpty(p.Name) && p.Name.Length >= 3 && !IsReservedWord(p.Name)) names.Add((p.Name, ph));
        }
        foreach (var lu in r.Inventory.Users)
            if (!_exempt.Contains(lu.Name) && lu.Sid != null && _accountPlaceholder.TryGetValue(lu.Sid, out var ph2)
                && !names.Any(n => n.Name.Equals(lu.Name, StringComparison.OrdinalIgnoreCase)) && lu.Name.Length >= 3)
                names.Add((lu.Name, ph2));

        // Profile folders: a deleted account's folder, a renamed account's old folder name or a Microsoft account's
        // shortened name never goes through an account lookup, so the folder name itself is masked — as a whole path
        // segment only. The placeholder is the account's own when it has one.
        var segments = new List<(string Name, string Placeholder)>();
        foreach (var (sid, profilePath) in r.Os.Profiles.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (SidText.SplitAccountSid(sid) == null) continue;
            var trimmed = profilePath.TrimEnd('\\');
            var folder = trimmed[(trimmed.LastIndexOf('\\') + 1)..];
            if (string.IsNullOrEmpty(folder) || IsReservedWord(folder)) continue;
            if (!_accountPlaceholder.TryGetValue(sid, out var ph3))
            {
                if (r.Names.TryGetValue(sid, out var pn) && pn.Name != null && _exempt.Contains(pn.Name)) continue;
                _accountPlaceholder[sid] = ph3 = $"<USER{++u}>";
            }
            segments.Add((folder, ph3));
        }
        // Account names shorter than 3 characters are not masked as words (too many false hits in ordinary text),
        // but they are masked where they stand as a whole path segment or after a backslash (DOMAIN\\jo).
        foreach (var p in accounts)
            if (!string.IsNullOrEmpty(p.Name) && p.Name.Length < 3 && !_exempt.Contains(p.Name)
                && _accountPlaceholder.TryGetValue(p.Sid, out var ph4))
                segments.Add((p.Name, ph4));
        foreach (var lu in r.Inventory.Users)
            if (lu.Name.Length < 3 && !_exempt.Contains(lu.Name) && lu.Sid != null && _accountPlaceholder.TryGetValue(lu.Sid, out var ph5))
                segments.Add((lu.Name, ph5));
        foreach (var (name, ph) in segments.DistinctBy(x => x.Name.ToLowerInvariant()).OrderByDescending(x => x.Name.Length))
            _segments.Add((new Regex(@"(?<=[\\/])" + Regex.Escape(name) + @"(?=[\\/`'""\s,;:)\]]|$)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline), ph));

        if (!string.IsNullOrEmpty(r.Os.ComputerName)) names.Add((r.Os.ComputerName, "<MACHINE>"));
        if (!string.IsNullOrEmpty(r.Os.DnsDomainName)) names.Add((r.Os.DnsDomainName, "<DOMAIN-DNS>"));
        if (!string.IsNullOrEmpty(r.Os.DomainName)) names.Add((r.Os.DomainName, "<DOMAIN>"));
        foreach (var dn in r.Names.Values.Select(p => p.Domain).Where(x => !string.IsNullOrEmpty(x)).Distinct(StringComparer.OrdinalIgnoreCase))
            if (!IsReservedWord(dn!) && !names.Any(n => n.Name.Equals(dn, StringComparison.OrdinalIgnoreCase)))
                if (!string.Equals(dn, r.Os.ComputerName, StringComparison.OrdinalIgnoreCase)) names.Add((dn!, "<DOMAIN>"));

        foreach (var (name, ph) in names.OrderByDescending(n => n.Name.Length))
            _text.Add((new Regex(@"(?<![\p{L}\p{N}_])" + Regex.Escape(name) + @"(?![\p{L}\p{N}_])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ph));
    }

    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "NT AUTHORITY", "BUILTIN", "NT SERVICE", "NT TASK", "APPLICATION PACKAGE AUTHORITY", "Window Manager", "Font Driver Host",
        "IIS APPPOOL", "NT VIRTUAL MACHINE", "Mandatory Label", "Everyone", "Users", "Administrators", "System", "Guest",
        "Administrator", "Windows", "Program", "Files", "Default", "Public", "Capability",
    };

    private bool IsReservedWord(string s) => Reserved.Contains(s) || _exempt.Contains(s);

    /// <summary>Label of a principal for export.</summary>
    public string Principal(string sid)
    {
        var p = _r.NameOf(sid);
        var split = SidText.SplitAccountSid(sid);
        var groups = GroupsText(sid);
        if (split == null)
        {
            var kbName = _kb.Principal(sid)?.Name;
            var display = p.Resolved ? p.Display : kbName ?? "(unresolved)";
            return Apply($"{display} ({sid})");
        }
        var (prefix, rid) = split.Value;
        bool local = string.Equals(prefix, _r.Os.MachineSid, StringComparison.OrdinalIgnoreCase);
        string scope = local ? "local" : "domain";
        if (rid < 1000)
        {
            var role = _kb.Principal(sid)?.Name ?? $"RID {rid}";
            if (!Enabled) return $"{p.Display} ({sid}; {role}){groups}";
            return $"{(local ? "<MACHINE>" : "<DOMAIN>")}\\{role} (RID {rid}, {scope}){groups}";
        }
        if (p.Name != null && _exempt.Contains(p.Name))
            return $"{p.Name}{groups}";
        if (!Enabled) return $"{p.Display} ({sid}){groups}";
        var ph = _accountPlaceholder.TryGetValue(sid, out var x) ? x : "<ACCOUNT>";
        var kind = p.Use switch
        {
            SidUse.User => $"{scope} account",
            SidUse.Group or SidUse.Alias or SidUse.WellKnownGroup => $"{scope} group",
            SidUse.Computer => $"{scope} computer",
            SidUse.DeletedAccount => "deleted account",
            _ => p.Resolved ? scope : $"unresolved {scope} SID",
        };
        return $"{ph} ({kind}){groups}";
    }

    private string GroupsText(string sid)
    {
        var groups = _r.Inventory.GroupsOf(sid).Select(g => g.Name).OrderBy(n => n).ToList();
        return groups.Count == 0 ? "" : " [" + string.Join(", ", groups.Select(Apply)) + "]";
    }

    /// <summary>Masks free text (paths, SDDL, remarks).</summary>
    public string Apply(string text)
    {
        if (!Enabled || string.IsNullOrEmpty(text)) return text;
        foreach (var (prefix, rep) in _sidPrefixes)
            text = text.Replace(prefix + "-", rep + "-", StringComparison.OrdinalIgnoreCase);
        foreach (var (rx, rep) in _text) text = rx.Replace(text, rep);
        foreach (var (rx, rep) in _segments) text = rx.Replace(text, rep);
        return text;
    }
}
