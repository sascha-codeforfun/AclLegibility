using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Security;

namespace AclLegibility.Export;

/// <summary>Builds the "Copy for AI" Markdown: precise, lossless (SDDL included), optionally masked,
/// ending with the knowledge-entry format so an answer can be pasted into knowledge.user.json.</summary>
public sealed class AiExport
{
    private readonly ScanResult _r;
    private readonly CompiledKb _kb;
    private readonly Classifier _cls;
    private readonly Masker _m;
    private readonly int _maxItems;

    public AiExport(ScanResult r, CompiledKb kb, Classifier cls, Masker masker, int maxItems)
    {
        _r = r; _kb = kb; _cls = cls; _m = masker; _maxItems = maxItems;
    }

    public static string AppVersion =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

    private void Header(StringBuilder sb, string title)
    {
        var os = _r.Os;
        sb.AppendLine($"# AclLegibility observation: {_m.Apply(title)}");
        sb.AppendLine();
        sb.AppendLine($"- Tool: AclLegibility {AppVersion}, knowledge base v{_kb.Kb.Doc.Version} ({_kb.Kb.EntryCount} entries, {_kb.Kb.UserEntryCount} from knowledge.user.json)");
        sb.AppendLine($"- OS: {os.FriendlyName} {os.DisplayVersion}, edition {os.EditionId}, build {os.Build}.{os.Ubr}, {os.InstallationType}, {os.Architecture}, UI language {os.UiLanguage}");
        sb.AppendLine($"- Knowledge target: {(os.IsTestedTarget ? os.TargetKey : $"untested OS (closest family: {os.FamilyKey})")}");
        sb.AppendLine($"- Domain joined: {(os.DomainJoined ? "yes" : "no")}");
        sb.AppendLine($"- Scanned: {_r.ScannedUtc:yyyy-MM-dd HH:mm} UTC{(_r.IsLive ? "" : " (from snapshot)")}; privileges: {string.Join(", ", _r.PrivilegesEnabled.DefaultIfEmpty("none"))}");
        sb.AppendLine(_m.Enabled
            ? $"- Masking: on — computer, domain and account names replaced by placeholders (<MACHINE>, <DOMAIN>, <USERn>); account SIDs show <MACHINE>/<DOMAINn> instead of the machine-specific part. Shown by name: {string.Join(", ", _m.ExemptNames.DefaultIfEmpty("none"))}."
            : "- Masking: off");
        foreach (var f in KnownFacts.InstallHistory(os)) sb.AppendLine($"- {f.Key}: {f.Value}");
        sb.AppendLine("- Classification meaning: Stock = shipped/set by Windows; Stock, modified = known Windows object that differs from the knowledge base in a way that gives someone more control; Stock, differs = known Windows object that differs from the reference install only in read/list rights or in which system account (SYSTEM/Administrators/TrustedInstaller) holds a right or owns it; Custom = admin/user/application activity; Unknown = not decidable yet; Trace = leftover of normal use, not configuration; Stock, per account = Windows' own per-account layout naming an account that exists. Objects with the same explicit entries as their parent are folded into the parent's finding.");
        sb.AppendLine();
    }

    public string Nodes(string title, IReadOnlyList<ScanNode> nodes, IReadOnlyList<Finding>? onlyFindings = null)
    {
        var sb = new StringBuilder();
        Header(sb, title);
        int total = nodes.Count;
        var take = nodes.Take(_maxItems).ToList();
        sb.AppendLine($"## Items ({take.Count}{(total > take.Count ? $" of {total}; the rest omitted" : "")})");
        sb.AppendLine();
        HashSet<Finding>? filter = onlyFindings != null ? new HashSet<Finding>(onlyFindings) : null;
        foreach (var n in take) Node(sb, n, filter);
        Footer(sb);
        return sb.ToString();
    }

    private void Node(StringBuilder sb, ScanNode n, HashSet<Finding>? filter)
    {
        var path = _m.Apply(n.FullPath);
        sb.AppendLine($"### `{path}`");
        sb.AppendLine();
        sb.AppendLine($"- Kind: {(n.IsDirectory ? "directory" : "file")}; attributes: {AttrText(n.Attributes)}" +
                      (n.IsDirectory ? "" : $"; size {n.Size:N0} bytes") +
                      (n.ShortName != null ? $"; 8.3 name {_m.Apply(n.ShortName)}" : "") +
                      ((n.Flags & NodeFlags.NotFollowed) != 0 ? "; reparse point not followed" : ""));

        var findings = n.Findings?.Where(f => filter == null || filter.Contains(f)).ToList() ?? new();
        if (n.Findings is { Count: > 0 } && findings.Count == 0) findings = n.Findings;
        foreach (var f in findings)
        {
            sb.AppendLine($"- Finding [{f.KindText}]: **{OriginText.Label(f.Origin)}**" +
                          (f.Confidence != Confidence.None ? $" (confidence: {OriginText.Label(f.Confidence)})" : "") +
                          (f.KbId != null ? $", knowledge entry `{f.KbId}`" : ", no knowledge entry") +
                          (f.UntestedOs ? ", untested OS" : "") + $" — {_m.Apply(f.Summary)}");
            if (f.Differences != null)
                foreach (var d in f.Differences) sb.AppendLine($"  - {_m.Apply(d)}");
        }

        var sd = _r.SdOf(n);
        if (sd != null)
        {
            sb.AppendLine($"- Owner: {(sd.Owner != null ? _m.Principal(sd.Owner) : "(none)")}; group: {(sd.Group != null ? _m.Principal(sd.Group) : "(none)")}");
            sb.AppendLine($"- DACL: {(sd.NullDacl ? "NULL (no access control)" : sd.DaclProtected ? "inheritance disabled (protected)" : "inherits from parent")}" +
                          $"{((n.Flags & NodeFlags.SdIncludesSacl) == 0 ? "; SACL not readable" : "")}");
            if (sd.Dacl is { Count: > 0 })
            {
                sb.AppendLine();
                sb.AppendLine("| # | Type | Principal | Rights | Applies to | Source |");
                sb.AppendLine("|---|------|-----------|--------|------------|--------|");
                foreach (var a in sd.Dacl) AceRow(sb, n, a);
                sb.AppendLine();
            }
            var audits = sd.AuditAces.ToList();
            if (audits.Count > 0)
            {
                sb.AppendLine("Auditing (SACL):");
                sb.AppendLine();
                sb.AppendLine("| # | Type | Principal | Rights | Applies to | Source |");
                sb.AppendLine("|---|------|-----------|--------|------------|--------|");
                foreach (var a in audits) AceRow(sb, n, a);
                sb.AppendLine();
            }
            if (sd.Label is { } l)
                sb.AppendLine($"- Integrity label: {Rights.LabelLevel(l.Sid)}, {Rights.LabelPolicy(l.Mask)}, {Rights.InheritShort(l.Flags)}{(l.IsInherited ? " inherited" : " explicit")}");
            sb.AppendLine($"- SDDL: `{_m.Apply(sd.Sddl)}`");
        }
        var known = KnownFacts.For(_r, _cls, n);
        if (known.Count > 0)
        {
            sb.AppendLine("- Known (read from disk and system):");
            foreach (var f in known) sb.AppendLine($"  - {f.Key}: {_m.Apply(f.AiValue != null && _m.Enabled ? f.AiValue : f.Value)}");
            if (n.Findings?.Any(f => f.Category == FindingCategory.Acl && f.Origin is Origin.Modified or Origin.Differs) == true)
                sb.AppendLine("  - Not recorded by Windows: who wrote this ACL, which build or program, and why.");
        }
        var x = n.Extra;
        if (x?.Streams != null)
            sb.AppendLine("- Alternate streams: " + string.Join(", ", x.Streams.Select(s => $"`{s.Name}` ({s.Size:N0} bytes)")));
        if (x?.Reparse is { } rp)
        {
            var tag = _kb.Tag(rp.Tag);
            sb.AppendLine($"- Reparse: tag 0x{rp.Tag:X8} ({tag?.Name ?? "unknown"}){(rp.Target != null ? $", target `{_m.Apply(rp.Target)}`" : "")}{(rp.Extra != null ? $", {_m.Apply(rp.Extra)}" : "")}");
        }
        if (!n.IsDirectory && n.LinkCount > 1) sb.AppendLine($"- Hard links: {n.LinkCount} names");
        if (x?.ObjectId is Guid g) sb.AppendLine($"- Object ID: {g:B}");
        if ((n.Flags & NodeFlags.CaseSensitive) != 0) sb.AppendLine("- Case-sensitive directory");
        if (x?.ErrorCode is int code && code != 0) sb.AppendLine($"- Read error {code} at {x.ErrorStage}: {Classifier.Win32Message(code)}");
        sb.AppendLine();
    }

    private void AceRow(StringBuilder sb, ScanNode n, AceInfo a)
    {
        string principal = a.IsLabel ? Rights.LabelLevel(a.Sid) : _m.Principal(a.Sid);
        string rights = $"{Rights.Short(a.Mask)} ({Rights.Hex(a.Mask)})";
        string applies = Rights.AppliesTo(a.Flags, n.IsDirectory) + (Rights.InheritShort(a.Flags) is { Length: > 0 } s ? " " + s : "");
        string source = a.IsInherited
            ? "inherited" + (AccessAnalysis.InheritedFrom(_r, n, a) is { } from ? $" from `{_m.Apply(from.FullPath)}`" : "")
            : "explicit";
        if (a.HasCondition) source += ", conditional";
        sb.AppendLine($"| {a.Index} | {a.TypeName} | {Esc(principal)} | {rights} | {applies} | {Esc(source)} |");
    }

    private static string Esc(string s) => s.Replace("|", "\\|");

    public static string AttrText(uint a)
    {
        var f = (FileAttributes)a;
        var parts = new List<string>();
        if (f.HasFlag(FileAttributes.ReadOnly)) parts.Add("R");
        if (f.HasFlag(FileAttributes.Hidden)) parts.Add("H");
        if (f.HasFlag(FileAttributes.System)) parts.Add("S");
        if (f.HasFlag(FileAttributes.Archive)) parts.Add("A");
        if (f.HasFlag(FileAttributes.Compressed)) parts.Add("C");
        if (f.HasFlag(FileAttributes.Encrypted)) parts.Add("E");
        if (f.HasFlag(FileAttributes.SparseFile)) parts.Add("Sparse");
        if (f.HasFlag(FileAttributes.ReparsePoint)) parts.Add("Reparse");
        if (f.HasFlag(FileAttributes.Offline)) parts.Add("Offline");
        if (f.HasFlag(FileAttributes.NotContentIndexed)) parts.Add("NotIndexed");
        if (f.HasFlag(FileAttributes.Temporary)) parts.Add("Temp");
        if (f.HasFlag(FileAttributes.IntegrityStream)) parts.Add("Integrity");
        if (f.HasFlag(FileAttributes.NoScrubData)) parts.Add("NoScrub");
        if ((a & 0x00040000) != 0) parts.Add("RecallOnOpen");
        if ((a & 0x00400000) != 0) parts.Add("RecallOnDataAccess");
        if ((a & 0x00080000) != 0) parts.Add("Pinned");
        if ((a & 0x00100000) != 0) parts.Add("Unpinned");
        return parts.Count == 0 ? "none" : string.Join(" ", parts);
    }

    public string Principal(string sid, IReadOnlyList<ScanNode> referencedBy, IReadOnlyList<(LocalGroup Group, IReadOnlyList<ScanNode> Nodes)> viaGroups)
    {
        var sb = new StringBuilder();
        Header(sb, "principal " + _m.Principal(sid));
        var entry = _kb.Principal(sid);
        sb.AppendLine($"## Principal {_m.Principal(sid)}");
        sb.AppendLine();
        sb.AppendLine($"- Knowledge: {(entry != null ? $"`principals/{entry.Id}` ({entry.Confidence}): {entry.Explain}" : "not in the knowledge base")}");
        var members = _r.Inventory.Groups.FirstOrDefault(g => string.Equals(g.Sid, sid, StringComparison.OrdinalIgnoreCase))?.Members;
        if (members != null)
            sb.AppendLine("- Members: " + (members.Count == 0 ? "(none)" : string.Join(", ", members.Select(mm => string.IsNullOrEmpty(mm.Sid) ? _m.Apply(mm.Name) : _m.Principal(mm.Sid)))));
        sb.AppendLine($"- Explicitly referenced on {referencedBy.Count} object(s)");
        sb.AppendLine();
        foreach (var n in referencedBy.Take(_maxItems))
            sb.AppendLine($"  - `{_m.Apply(n.FullPath)}` — {string.Join("; ", AcesFor(n, sid))}");
        foreach (var (g, nodes) in viaGroups)
        {
            sb.AppendLine();
            sb.AppendLine($"- Through group {_m.Apply(g.Name)}: {nodes.Count} object(s)");
            foreach (var n in nodes.Take(Math.Max(10, _maxItems / 10)))
                sb.AppendLine($"  - `{_m.Apply(n.FullPath)}` — {string.Join("; ", AcesFor(n, g.Sid!))}");
        }
        Footer(sb);
        return sb.ToString();
    }

    private IEnumerable<string> AcesFor(ScanNode n, string sid)
    {
        var sd = _r.SdOf(n);
        if (sd == null) yield break;
        foreach (var a in (sd.Dacl ?? new()).Concat(sd.AuditAces))
            if (!a.IsInherited && string.Equals(a.Sid, sid, StringComparison.OrdinalIgnoreCase))
                yield return $"{a.TypeName} {Rights.Short(a.Mask)} {Rights.AppliesTo(a.Flags, n.IsDirectory)}";
    }

    public string Shares(IReadOnlyList<ShareEntry> shares)
    {
        var sb = new StringBuilder();
        Header(sb, "shares");
        sb.AppendLine("## Shares");
        sb.AppendLine();
        foreach (var s in shares)
        {
            var (origin, explain, kbId, conf) = _cls.ClassifyShare(s);
            sb.AppendLine($"### `{_m.Apply(s.Name)}` → `{_m.Apply(s.Path ?? "")}`");
            sb.AppendLine($"- Type: {s.TypeText}; remark: {_m.Apply(s.Remark ?? "")}");
            sb.AppendLine($"- Classification: **{OriginText.Label(origin)}** ({OriginText.Label(conf)}){(kbId != null ? $", `{kbId}`" : "")}");
            if (s.SecurityDescriptor != null)
            {
                var sd = new SdInfo(s.SecurityDescriptor);
                sb.AppendLine("- Share permissions: " + (sd.Dacl == null ? "none / default (Everyone read)" :
                    string.Join("; ", sd.Dacl.Select(a => $"{a.TypeName} {_m.Principal(a.Sid)} {ShareRights(a.Mask)}"))));
                sb.AppendLine($"- SDDL: `{_m.Apply(sd.Sddl)}`");
            }
            else sb.AppendLine("- Share permissions: default (no descriptor stored)");
            sb.AppendLine();
        }
        Footer(sb);
        return sb.ToString();
    }

    public static string ShareRights(uint mask)
    {
        var n = Rights.Normalize(mask);
        if ((n & 0x1F01FF) == 0x1F01FF) return "Full control";
        if ((n & 0x1301BF) == 0x1301BF) return "Change";
        if ((n & 0x1200A9) == 0x1200A9) return "Read";
        return Rights.Short(mask);
    }

    private void Footer(StringBuilder sb)
    {
        sb.AppendLine("## Request");
        sb.AppendLine();
        sb.AppendLine("Please identify, for each item classified Unknown or Stock-modified (and for any Stock item you think is wrong): what Windows component, role, feature or common product sets it, whether it is stock on this OS build, and why it is configured that way.");
        sb.AppendLine("Answer with knowledge entries I can paste into `knowledge.user.json` (JSON with comments allowed). Use `\"confidence\": \"observed\"` only for things seen on a clean install of this exact OS, otherwise `\"assumed\"`. Format:");
        sb.AppendLine();
        sb.AppendLine("```json");
        sb.AppendLine("{");
        sb.AppendLine("  \"paths\": [");
        sb.AppendLine("    { \"id\": \"unique-id\", \"os\": [\"win10\", \"win11\", \"srv2019\", \"srv2022\", \"srv2025\"], \"path\": \"%SystemRoot%\\\\Some\\\\Folder\",");
        sb.AppendLine("      \"owner\": \"TI\", \"protected\": true, \"mode\": \"exact\",");
        sb.AppendLine("      \"aces\": [\"A;OICI;F;SY\", \"A;OICIIO;RX;BU\", \"D;;RD;WD;includes\"],");
        sb.AppendLine("      \"origin\": \"stock\", \"confidence\": \"assumed\", \"explain\": \"Why Windows sets it this way.\" }");
        sb.AppendLine("  ],");
        sb.AppendLine("  (A path entry may also list \"variants\": [ { \"label\": \"where it was seen\", \"aces\": [...], \"owner\": ..., \"protected\": ... } ] — other ACLs Windows is known to write there; a match counts as stock.)");
        sb.AppendLine("  \"patterns\": [ { \"id\": \"...\", \"under\": [\"%ProgramData%\\\\Vendor\"], \"owners\": [\"SY\"], \"principals\": [\"SY\", \"BA\", \"S-1-5-80-*\"], \"origin\": \"stock\", \"confidence\": \"assumed\", \"explain\": \"...\" } ],");
        sb.AppendLine("  \"streams\": [ { \"id\": \"...\", \"name\": \"StreamName\", \"under\": [\"%SystemRoot%\"], \"origin\": \"stock\", \"confidence\": \"assumed\", \"explain\": \"...\" } ],");
        sb.AppendLine("  \"reparsePoints\": [ { \"id\": \"...\", \"path\": \"%ProgramData%\\\\Name\", \"tag\": \"junction\", \"target\": \"{parent}\\\\..\\\\Other\", \"expected\": true, \"origin\": \"stock\", \"confidence\": \"assumed\", \"explain\": \"...\" } ],");
        sb.AppendLine("  (\"target\": where the link must point, {parent} = the folder holding it; a different target is Modified. \"expected\": Windows creates it, absence is reported.)");
        sb.AppendLine("  \"items\": [ { \"id\": \"...\", \"path\": \"%ProgramData%\\\\Folder\" or \"name\": \"file.ext\", \"under\": [\"...\"], \"explain\": \"what it is and who creates it\", \"how\": \"how to change or switch it off\" } ],");
        sb.AppendLine("  (\"items\" only explain what a file or folder is; they change no classification.)");
        sb.AppendLine("  \"quirks\": [ { \"id\": \"...\", \"category\": \"HardLink\", \"under\": [\"%ProgramFiles%\\\\X\"], \"origin\": \"stock\", \"confidence\": \"assumed\", \"explain\": \"...\" } ],");
        sb.AppendLine("  \"principals\": [ { \"id\": \"...\", \"sid\": \"S-1-5-80-...\", \"name\": \"NT SERVICE\\\\Name\", \"builtin\": true, \"confidence\": \"assumed\", \"explain\": \"...\" } ]");
        sb.AppendLine("}");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("ACE format: `type;flags;rights;principal[;options]`. type A=allow, D=deny, AU=audit. flags: OI CI IO NP (concatenated). rights: F M RX R W, or bits joined with + (RD WD AD REA WEA X DC RA WA DE RC WDAC WO S), or hex 0x…. principal: SID or alias (SY BA BU AU WD CO OW TI AC RAC IU SU NU LS NS IUSR IIS_IUSRS) or $OWNER (the object's owner) or $PROFILE (the account Windows' profile list assigns to the profile folder) or cap:<capability name>; in pattern principals also $ANYPROFILE (any account with a profile), $NAMESID (an account SID written in the path), $FILENAME (the account named like the file), $ORPHAN (a proven deleted account). options: includes (mask may have more bits), optional.");
        sb.AppendLine("Path variables: %SystemDrive% %SystemRoot% %ProgramFiles% %ProgramFiles(x86)% %ProgramData% %ProfilesDir% %PUBLIC%. `*` matches within one path segment, `**` any depth, `?:` any drive. `os` values: win10, win11, srv2019, srv2022, srv2025 (omit for all). `origin`: stock, peraccount, trace, custom, unknown, modified (stock is the default). `confidence`: documented, observed, assumed, unverified.");
    }
}
