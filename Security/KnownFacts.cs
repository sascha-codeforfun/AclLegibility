using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Native;

namespace AclLegibility.Security;

/// <summary>One fact read from the disk or the system. AiValue replaces Value in Copy for AI when it would identify the machine.</summary>
public sealed record Fact(string Key, string Value, string? AiValue = null, bool Warn = false);

/// <summary>What a scheduled task's definition file says about itself (Task Scheduler's own XML).</summary>
public sealed class TaskInfo
{
    public string? Author, Date, Version, Source, Uri, Description;
    public string? UserId, GroupId, LogonType, RunLevel;
    public List<string> Commands = new();
    public bool Enabled = true;
}

/// <summary>
/// The "Known" block: facts that are on disk or in the system, kept apart from what Windows never records
/// (who wrote an ACL, which build, why). Nothing here is a guess.
/// </summary>
public static class KnownFacts
{
    /// <summary>Facts about one object. Live reads (time stamps, task files) only for a scan of this machine.</summary>
    public static List<Fact> For(ScanResult r, Classifier cls, ScanNode n)
    {
        var facts = new List<Fact>();
        var times = r.IsLive ? LiveReads.Times(n.FullPath) : null;
        if (times is null && n.Created > 0)
            facts.Add(new("Created", $"{DateTime.FromFileTimeUtc(n.Created).ToLocalTime():yyyy-MM-dd HH:mm:ss}"));
        if (times is { } t)
        {
            if (t.Created != DateTime.MinValue) facts.Add(new("Created", $"{t.Created:yyyy-MM-dd HH:mm:ss}"));
            if (t.Changed != DateTime.MinValue)
                facts.Add(new("Metadata last changed", $"{t.Changed:yyyy-MM-dd HH:mm:ss} — NTFS sets this on any metadata change, "
                    + "an ACL write included, so the current ACL was written at this moment or earlier"));
            if (!n.IsDirectory && t.Written != DateTime.MinValue) facts.Add(new("Contents last written", $"{t.Written:yyyy-MM-dd HH:mm:ss}"));
        }
        if (r.SdOf(n) is { } sd && sd.ParseError == null)
        {
            var flags = new List<string>();
            if (sd.DaclProtected) flags.Add("protected (P)");
            if (sd.DaclAutoInherited) flags.Add("auto-inherited (AI)");
            facts.Add(new("DACL flags", flags.Count == 0 ? "none" : string.Join(", ", flags)
                + (sd.DaclProtected && !sd.DaclAutoInherited ? " — written without the auto-inherit flag, so by a different code path than ACLs that carry it" : "")));
        }
        if (SameSecond(r, n) is { } together) facts.Add(together);
        foreach (var g in VersionOneGuids(n.Name))
            facts.Add(new("GUID in name", $"{g.Guid:D}: made {g.Time:yyyy-MM-dd HH:mm} UTC on a {g.Kind} ({FormatMac(g.Node)})",
                $"{g.Guid.ToString("D")[..23]}-…: made {g.Time:yyyy-MM-dd HH:mm} UTC on a {g.Kind} (address masked)"));
        if (r.IsLive && !n.IsDirectory && Classifier.TaskCommand(n, r.Os) != null && ReadTask(n.FullPath) is { } task)
            AddTaskFacts(facts, task, r, cls);
        if (r.IsLive && !n.IsDirectory && n.Name.EndsWith(".pol", StringComparison.OrdinalIgnoreCase) && PolicyEntries(n.FullPath) is { Count: > 0 } pol)
            facts.Add(new("Policies listed", string.Join("\n", pol.Take(40)) + (pol.Count > 40 ? $"\n… {pol.Count - 40:N0} more" : "")));
        return facts;
    }

    /// <summary>This installation's history, for findings that differ from the reference install.</summary>
    public static List<Fact> InstallHistory(OsInfo os)
    {
        var facts = new List<Fact>();
        if (os.CurrentInstallUtc is { } cur)
            facts.Add(new("This Windows", $"build {os.Build}.{os.Ubr}; installed or last upgraded in place on {cur.ToLocalTime():yyyy-MM-dd}"));
        foreach (var u in os.UpgradedFrom) facts.Add(new("Upgraded from", u.Describe()));
        if (os.UpgradedFrom.Count == 0 && os.CurrentInstallUtc != null) facts.Add(new("Upgraded from", "nothing recorded (no Source OS key): a clean install, or upgrades that left no key"));
        return facts;
    }

    public const string NotRecorded = "Who wrote this ACL, which Windows build or program did it, and why: Windows does not record this. "
                                      + "The facts above bound it; any cause beyond them is a guess.";

    // ---- created in the same second -----------------------------------------------------------

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ScanResult, Dictionary<long, List<ScanNode>>> _bySecond = new();

    /// <summary>Other objects created in the same second (outside this object's own branch and its parents). Objects made
    /// in one second come from one step — an installer, an update, a copy — so naming them ties things together.</summary>
    public static Fact? SameSecond(ScanResult r, ScanNode n)
    {
        if (n.Created <= 0) return null;
        var index = _bySecond.GetValue(r, BuildIndex);
        if (!index.TryGetValue(n.Created / 10_000_000, out var all)) return null;
        var others = all.Where(x => x != n && !IsWithin(x, n) && !IsWithin(n, x)).ToList();
        if (others.Count == 0) return null;
        if (others.Count <= 6)
            return new("Created together with", string.Join("\n", others.Select(x => x.FullPath)));
        var examples = others.GroupBy(x => x.Parent).OrderByDescending(g => g.Count()).Take(3)
            .Select(g => g.Key == null ? g.First().FullPath : $"{g.Key.FullPath}\\ ({g.Count():N0})");
        return new("Created together with", $"{others.Count:N0} other objects in the same second — typical for an installation, "
            + "an update or a copy. Most of them in:\n" + string.Join("\n", examples));
    }

    private static bool IsWithin(ScanNode x, ScanNode ancestor)
    {
        for (var p = x.Parent; p != null; p = p.Parent) if (p == ancestor) return true;
        return false;
    }

    private static Dictionary<long, List<ScanNode>> BuildIndex(ScanResult r)
    {
        var index = new Dictionary<long, List<ScanNode>>();
        var stack = new Stack<ScanNode>();
        foreach (var root in r.Roots) stack.Push(root);
        while (stack.Count > 0)
        {
            var x = stack.Pop();
            if (x.Created > 0)
            {
                var key = x.Created / 10_000_000;
                if (!index.TryGetValue(key, out var list)) index[key] = list = new List<ScanNode>(2);
                list.Add(x);
            }
            if (x.Children != null) foreach (var c in x.Children) stack.Push(c);
        }
        return index;
    }

    // ---- Group Policy registry records (Registry.pol / ntuser.pol) ------------------------------

    /// <summary>The key\\value names a policy file lists (PReg format: "[key;value;type;size;data]" in UTF-16).</summary>
    public static List<string>? PolicyEntries(string path)
    {
        var b = LiveReads.ReadBytes(path, 1024 * 1024);
        if (b == null || b.Length < 8 || b[0] != 'P' || b[1] != 'R' || b[2] != 'e' || b[3] != 'g') return null;
        var list = new List<string>();
        int pos = 8;
        string ReadStr()
        {
            int start = pos;
            while (pos + 1 < b.Length && !(b[pos] == ';' && b[pos + 1] == 0)) pos += 2;
            var str = Encoding.Unicode.GetString(b, start, Math.Max(0, pos - start)).TrimEnd('\0');
            pos += 2;
            return str;
        }
        try
        {
            while (pos + 2 < b.Length)
            {
                if (b[pos] != '[' || b[pos + 1] != 0) break;
                pos += 2;
                var key = ReadStr();
                var value = ReadStr();
                pos += 4 + 2;                                       // type + ';'
                int size = BitConverter.ToInt32(b, pos); pos += 4 + 2; // size + ';'
                pos += Math.Max(0, size);
                pos += 2;                                           // ']'
                if (!value.StartsWith("**", StringComparison.Ordinal)) list.Add(key + "\\" + value);
            }
        }
        catch { }
        return list;
    }

    // ---- scheduled tasks ----------------------------------------------------------------------

    public static TaskInfo? ReadTask(string path)
    {
        var bytes = LiveReads.ReadBytes(path, 512 * 1024);
        if (bytes == null || bytes.Length == 0) return null;
        try
        {
            var doc = new XmlDocument { XmlResolver = null };
            using (var ms = new System.IO.MemoryStream(bytes))
            using (var xr = XmlReader.Create(ms, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
                doc.Load(xr);
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("t", doc.DocumentElement?.NamespaceURI ?? "");
            string? V(string xp) => doc.SelectSingleNode(xp, ns)?.InnerText?.Trim() is { Length: > 0 } s ? s : null;
            var info = new TaskInfo
            {
                Author = V("/t:Task/t:RegistrationInfo/t:Author"),
                Date = V("/t:Task/t:RegistrationInfo/t:Date"),
                Version = V("/t:Task/t:RegistrationInfo/t:Version"),
                Source = V("/t:Task/t:RegistrationInfo/t:Source"),
                Uri = V("/t:Task/t:RegistrationInfo/t:URI"),
                Description = V("/t:Task/t:RegistrationInfo/t:Description"),
                UserId = V("/t:Task/t:Principals/t:Principal/t:UserId"),
                GroupId = V("/t:Task/t:Principals/t:Principal/t:GroupId"),
                LogonType = V("/t:Task/t:Principals/t:Principal/t:LogonType"),
                RunLevel = V("/t:Task/t:Principals/t:Principal/t:RunLevel"),
                Enabled = !string.Equals(V("/t:Task/t:Settings/t:Enabled"), "false", StringComparison.OrdinalIgnoreCase),
            };
            foreach (XmlNode ex in doc.SelectNodes("/t:Task/t:Actions/t:Exec", ns)!)
            {
                var cmd = ex.SelectSingleNode("t:Command", ns)?.InnerText?.Trim();
                var args = ex.SelectSingleNode("t:Arguments", ns)?.InnerText?.Trim();
                if (!string.IsNullOrEmpty(cmd)) info.Commands.Add(cmd + (string.IsNullOrEmpty(args) ? "" : " " + args));
            }
            foreach (XmlNode ch in doc.SelectNodes("/t:Task/t:Actions/t:ComHandler/t:ClassId", ns)!)
                info.Commands.Add("COM handler " + ch.InnerText.Trim());
            return info;
        }
        catch { return null; }
    }

    /// <summary>Who a task runs as, as an account SID when the definition names one (a SID or a well-known name).</summary>
    public static string? RunsAsSid(TaskInfo t)
    {
        var id = t.UserId ?? t.GroupId;
        if (string.IsNullOrEmpty(id)) return null;
        if (id.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return id;
        return id.ToUpperInvariant() switch
        {
            "SYSTEM" or "NT AUTHORITY\\SYSTEM" or "LOCALSYSTEM" => "S-1-5-18",
            "LOCALSERVICE" or "LOCAL SERVICE" or "NT AUTHORITY\\LOCALSERVICE" or "NT AUTHORITY\\LOCAL SERVICE" => "S-1-5-19",
            "NETWORKSERVICE" or "NETWORK SERVICE" or "NT AUTHORITY\\NETWORKSERVICE" or "NT AUTHORITY\\NETWORK SERVICE" => "S-1-5-20",
            _ => null,
        };
    }

    private static void AddTaskFacts(List<Fact> facts, TaskInfo t, ScanResult r, Classifier cls)
    {
        if (t.Author != null) facts.Add(new("Task author", t.Author));
        if (t.Date != null) facts.Add(new("Task date", t.Date + " — as written by whoever registered the task; not a time stamp Windows checks"));
        if (t.Version != null) facts.Add(new("Task version", t.Version));
        if (t.Source != null) facts.Add(new("Task source", t.Source));
        if (t.Uri != null) facts.Add(new("Task URI", t.Uri));
        var who = t.UserId ?? (t.GroupId != null ? "group " + t.GroupId : null);
        if (who != null)
        {
            var sid = RunsAsSid(t);
            var name = sid != null ? r.NameOf(sid).Display : who;
            facts.Add(new("Runs as", name + (t.RunLevel != null ? $" · {t.RunLevel}" : "") + (t.LogonType != null ? $" · {t.LogonType}" : "")));
            if (sid != null && cls.OrphanStateOf(sid) == OrphanState.Proven)
                facts.Add(new("Dead task", "Runs as a deleted account — it will never run again. Remove it through Task Scheduler (line in the finding above).", Warn: true));
        }
        foreach (var c in t.Commands.Take(3)) facts.Add(new("Runs", c));
        if (!t.Enabled) facts.Add(new("Enabled", "no (disabled in its definition)"));
    }

    // ---- scheduled-task SIDs (S-1-5-87) ----------------------------------------------------------

    /// <summary>The virtual-account SID Windows derives from a name the same way as service SIDs (S-1-5-80): SHA-1 of the
    /// upper-cased name in UTF-16, read as five 32-bit sub-authorities. Used only to name a task SID when it matches exactly.</summary>
    public static string DeriveSid(string authority, string name)
    {
        var hash = SHA1.HashData(Encoding.Unicode.GetBytes(name.ToUpperInvariant()));
        var sb = new StringBuilder(authority);
        for (int i = 0; i < 5; i++) sb.Append('-').Append(BitConverter.ToUInt32(hash, i * 4));
        return sb.ToString();
    }

    /// <summary>Task-name candidates for a task file: its name, its path in Task Scheduler with and without the leading "\".</summary>
    public static IEnumerable<string> TaskNameCandidates(string relativePath)
    {
        var rel = relativePath.Trim('\\');
        yield return rel[(rel.LastIndexOf('\\') + 1)..];
        yield return rel;
        yield return "\\" + rel;
    }

    // ---- version-1 GUIDs -------------------------------------------------------------------------

    private static readonly Regex GuidRx = new(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.Compiled);

    /// <summary>GUIDs in a name that are version 1 (time-based): they carry the moment they were made and a network address.</summary>
    public static IEnumerable<(Guid Guid, DateTime Time, byte[] Node, string Kind)> VersionOneGuids(string name)
    {
        foreach (Match m in GuidRx.Matches(name))
        {
            var s = m.Value;
            if (s[14] != '1') continue;                          // version nibble
            if ("89abAB".IndexOf(s[19]) < 0) continue;            // RFC 4122 variant
            if (!Guid.TryParse(s, out var g)) continue;
            var timeLow = Convert.ToUInt64(s[..8], 16);
            var timeMid = Convert.ToUInt64(s.Substring(9, 4), 16);
            var timeHi = Convert.ToUInt64(s.Substring(15, 3), 16);
            var ticks100ns = (timeHi << 48) | (timeMid << 32) | timeLow;
            DateTime time;
            try { time = new DateTime(1582, 10, 15, 0, 0, 0, DateTimeKind.Utc).AddTicks((long)ticks100ns); }
            catch { continue; }
            if (time.Year < 1995 || time > DateTime.UtcNow.AddYears(1)) continue;
            var node = Convert.FromHexString(s[24..]);
            yield return (g, time, node, NodeKind(node));
        }
    }

    /// <summary>What kind of network adapter an address belongs to, from a short built-in list of vendor prefixes.</summary>
    public static string NodeKind(byte[] node)
    {
        if ((node[0] & 0x01) != 0) return "machine without a usable network address (random node)";
        var oui = $"{node[0]:X2}{node[1]:X2}{node[2]:X2}";
        return oui switch
        {
            "000D3A" or "0003FF" or "00125A" or "0017FA" or "001DD8" or "0050F2" or "7C1E52" => "Microsoft network adapter (Azure range: likely Microsoft's own build machines)",
            "00155D" => "Hyper-V virtual adapter (a Hyper-V host or VM)",
            "000C29" or "005056" or "000569" or "001C14" => "VMware virtual adapter",
            "080027" or "0A0027" => "VirtualBox virtual adapter",
            "525400" => "QEMU/KVM virtual adapter",
            _ => (node[0] & 0x02) != 0 ? "locally administered address (virtual or randomised)" : "hardware network adapter",
        };
    }

    public static string FormatMac(byte[] node) => string.Join("-", node.Select(b => b.ToString("X2")));
}
