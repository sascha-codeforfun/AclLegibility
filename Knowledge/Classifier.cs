using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel;
using AclLegibility.Model;
using AclLegibility.Security;

namespace AclLegibility.Knowledge;

/// <summary>Turns raw scan data into findings, each tagged stock / modified / custom / unknown.</summary>
public sealed class Classifier
{
    private readonly ScanResult _r;
    private readonly CompiledKb _kb;
    private readonly bool _untested;

    /// <summary>Breakpoints that reference a SID in an explicit ACE (DACL or SACL).</summary>
    public Dictionary<string, List<ScanNode>> ExplicitRefs { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How many objects each SID owns.</summary>
    public Dictionary<string, int> OwnerCounts { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Folder → the permissions finding that stands for its explicit entries (for folding).</summary>
    private readonly Dictionary<ScanNode, Finding> _aclHead = new();
    private string?[] _signatures = Array.Empty<string?>();

    public Classifier(ScanResult result, CompiledKb kb)
    {
        _r = result; _kb = kb; _untested = !result.Os.IsTestedTarget;
    }

    public void Run(Action<string>? status = null)
    {
        status?.Invoke("Parsing security descriptors");
        var raws = _r.Descriptors.Snapshot();
        var infos = new SdInfo?[raws.Count];
        Parallel.For(0, raws.Count, i => infos[i] = new SdInfo(raws[i]));
        _r.SdInfos = infos;

        NameTaskSids(infos);

        // Give names to SIDs Windows cannot resolve (capabilities, loaded snapshots) from the knowledge base.
        foreach (var info in infos)
            if (info != null)
                foreach (var sid in info.AllSids())
                    if (!string.IsNullOrEmpty(sid) && !_r.NameOf(sid).Resolved && _kb.Principal(sid) is { Name: { } kbName } p && p.Sid != null)
                        _r.Names[sid] = new PrincipalName { Sid = sid, Name = kbName, Use = SidUse.WellKnownGroup };

        _signatures = new string?[infos.Length];
        ExplicitRefs.Clear();
        OwnerCounts.Clear();
        _aclHead.Clear();

        status?.Invoke("Classifying");
        var findings = new List<Finding>();
        var order = new List<ScanNode>();
        foreach (var n in _r.AllNodes())
        {
            order.Add(n);
            n.Findings = null;
            n.SubtreeAttention = 0;
            n.SubtreeWorst = Origin.None;
            n.SubtreeModified = 0;
            n.SubtreeWorstRest = Origin.None;
            n.SubtreeLinks = 0;
            ClassifyNode(n, findings);
        }
        status?.Invoke("Listing stock items not present");
        _r.NotPresent = new();
        _r.NotPresentUnlisted = new();
        AddMissingStockItems();
        if (!_r.Cancelled) AddMissingStockLinks();
        AddSupersededPackages(findings);
        foreach (var f in findings)
            if (f.Folded > 0) f.Summary += $" · plus {(f.Folded == 1 ? "1 object" : $"{f.Folded:N0} objects")} below with the same explicit entries";
        _aclHead.Clear();
        _r.Findings = findings;

        status?.Invoke("Summarising");
        for (int i = order.Count - 1; i >= 0; i--)
        {
            var n = order[i];
            // Counts objects, not findings: one file with a stream, a hard link and an object ID is one object.
            int own = 0;
            var worst = Origin.None;
            if (n.Findings != null)
                foreach (var f in n.Findings)
                    if (f.NeedsAttention) { own = 1; if (f.Origin > worst) worst = f.Origin; }
            n.SubtreeAttention += own;
            if (worst == Origin.Modified) n.SubtreeModified++;
            else if (worst > n.SubtreeWorstRest) n.SubtreeWorstRest = worst;
            if (worst > n.SubtreeWorst) n.SubtreeWorst = worst;
            if (n.IsLink || n.Findings?.Any(f => f.Category == FindingCategory.Link) == true) n.SubtreeLinks++;
            if (n.Parent != null)
            {
                var p = n.Parent;
                p.SubtreeAttention += n.SubtreeAttention;
                p.SubtreeModified += n.SubtreeModified;
                p.SubtreeLinks += n.SubtreeLinks;
                if (n.SubtreeWorst > p.SubtreeWorst) p.SubtreeWorst = n.SubtreeWorst;
                if (n.SubtreeWorstRest > p.SubtreeWorstRest) p.SubtreeWorstRest = n.SubtreeWorstRest;
            }
        }
    }

    private static readonly System.Text.RegularExpressions.Regex PackageFolder = new(
        @"^(?<name>[^_]+)_(?<ver>\d+\.\d+\.\d+\.\d+)_(?<arch>x64|x86|arm64|arm|neutral)_(?<res>[^_]*)_(?<pub>[a-z0-9]{13})$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Package folders named Name_Version_Arch_Resource_PublisherId that have a newer version of the same package
    /// next to them: older ones are listed quietly as superseded (Trace) with their size. Whether Windows still has them
    /// registered for some account is not checked — that needs the package manager; the finding gives the command.</summary>
    private void AddSupersededPackages(List<Finding> all)
    {
        // Windows keeps a record of every package version in ProgramData\Microsoft\Windows\AppRepository\Packages and
        // removes it together with the package. A record whose package folder is in WindowsApps belongs to that finding
        // (one version, counted once); a record without such a folder stays a finding of its own.
        string? repository = _r.Os.Paths.TryGetValue("ProgramData", out var pd) ? pd.TrimEnd('\\') + @"\Microsoft\Windows\AppRepository\Packages" : null;
        string? windowsApps = _r.Os.Paths.TryGetValue("ProgramFiles", out var pf) ? pf.TrimEnd('\\') + @"\WindowsApps" : null;
        foreach (var parent in _r.AllNodes())
        {
            if (parent.Children is not { Count: > 1 } kids) continue;
            bool isRepository = repository != null && parent.FullPath.TrimEnd('\\').Equals(repository, StringComparison.OrdinalIgnoreCase);
            bool isWindowsApps = windowsApps != null && parent.FullPath.TrimEnd('\\').Equals(windowsApps, StringComparison.OrdinalIgnoreCase);
            var groups = new Dictionary<string, List<(ScanNode Node, Version Ver)>>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in kids)
            {
                if (!c.IsDirectory) continue;
                var m = PackageFolder.Match(c.Name);
                if (!m.Success || !Version.TryParse(m.Groups["ver"].Value, out var v)) continue;
                var key = $"{m.Groups["name"].Value}|{m.Groups["arch"].Value}|{m.Groups["res"].Value}|{m.Groups["pub"].Value}";
                if (!groups.TryGetValue(key, out var list)) groups[key] = list = new();
                list.Add((c, v));
            }
            foreach (var list in groups.Values)
            {
                if (list.Count < 2) continue;
                list.Sort((a, b) => b.Ver.CompareTo(a.Ver));
                var newest = list[0];
                for (int i = 1; i < list.Count; i++)
                {
                    var (node, ver) = list[i];
                    if (isRepository && windowsApps != null && _r.FindByPath(windowsApps + "\\" + node.Name) != null) continue;
                    var record = isWindowsApps && repository != null ? _r.FindByPath(repository + "\\" + node.Name) : null;
                    long size = 0; int objects = 0;
                    var st = new Stack<ScanNode>(); st.Push(node);
                    while (st.Count > 0) { var x = st.Pop(); objects++; size += x.Size; if (x.Children != null) foreach (var y in x.Children) st.Push(y); }
                    var name = PackageFolder.Match(node.Name).Groups["name"].Value;
                    var pub = PackageFolder.Match(node.Name).Groups["pub"].Value;
                    var f = new Finding
                    {
                        Node = node, Category = FindingCategory.Superseded, Origin = Origin.Trace, Confidence = Confidence.Documented,
                        Summary = $"Superseded: version {ver}, one of {list.Count} versions here, newest {newest.Ver} · {objects:N0} objects, {SizeText(size)}",
                        Explanation = "A newer version of the same package sits in the same folder. Package folders are named "
                            + "Name_Version_Architecture_Resource_PublisherId; an update installs the new version beside the old one, and the old "
                            + "one is normally removed once no account on the machine still uses it. Whether one still does is not recorded on "
                            + "disk — ask Windows (admin PowerShell):\n"
                            + $"Get-AppxPackage -AllUsers | Where-Object PackageFamilyName -like '{name}_{pub}' | Select-Object Name, Version, PackageUserInformation\n"
                            + "A version Windows no longer lists is a leftover. The newest version here can still be older than what actually runs "
                            + "(an app can switch installers)."
                            + (record != null ? $"\nWindows' own record of this version: {record.FullPath} — it goes together with the package." : "")
                            + (isRepository ? "\nThis is Windows' record of a package version whose folder is not in WindowsApps." : ""),
                    };
                    Add(node, f, all);
                }
            }
        }
    }

    private static string SizeText(long b) =>
        b >= 1L << 30 ? $"{b / (double)(1L << 30):0.##} GB" : b >= 1L << 20 ? $"{b / (double)(1L << 20):0.#} MB" : b >= 1024 ? $"{b / 1024.0:0.#} KB" : $"{b:N0} bytes";

    /// <summary>Scheduled-task SIDs (S-1-5-87-…) Windows could not name: derive the SID of every task name in Task Scheduler's
    /// store and name a SID only when it matches exactly ("NT TASK\name"). Unmatched SIDs stay unnamed.</summary>
    private void NameTaskSids(SdInfo?[] infos)
    {
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var info in infos)
            if (info != null)
                foreach (var sid in info.AllSids())
                    if (sid != null && sid.StartsWith("S-1-5-87-", StringComparison.Ordinal) && !_r.NameOf(sid).Resolved) wanted.Add(sid);
        if (wanted.Count == 0 || !_r.Os.Paths.TryGetValue("SystemRoot", out var sr)) return;
        var storePath = sr.TrimEnd('\\') + "\\System32\\Tasks";
        if (_r.FindByPath(storePath) is not { } store) return;
        var stack = new Stack<(ScanNode Node, string Rel)>();
        stack.Push((store, ""));
        while (stack.Count > 0 && wanted.Count > 0)
        {
            var (node, rel) = stack.Pop();
            foreach (var c in node.Children ?? Enumerable.Empty<ScanNode>())
            {
                var crel = rel + "\\" + c.Name;
                if (c.IsDirectory) { stack.Push((c, crel)); continue; }
                foreach (var cand in KnownFacts.TaskNameCandidates(crel))
                {
                    var sid = KnownFacts.DeriveSid("S-1-5-87", cand);
                    if (!wanted.Remove(sid)) continue;
                    _r.Names[sid] = new PrincipalName { Sid = sid, Domain = "NT TASK", Name = cand.TrimStart('\\'), Use = SidUse.WellKnownGroup };
                }
            }
        }
    }

    private void Add(ScanNode n, Finding f, List<Finding> all)
    {
        if (_untested && f.Origin == Origin.Stock) f.UntestedOs = true;
        (n.Findings ??= new()).Add(f);
        all.Add(f);
    }

    private void ClassifyNode(ScanNode n, List<Finding> all)
    {
        string? path = null;
        string[]? segs = null;
        string P() => path ??= n.FullPath;
        string[] S() => segs ??= PathPattern.Split(P());

        // --- unreadable --------------------------------------------------------------------
        if ((n.Flags & (NodeFlags.Unreadable | NodeFlags.ListFailed)) != 0)
        {
            var x = n.Extra;
            int code = x?.ErrorCode ?? 0;
            var cause = ReadCauses.Of(code);
            var step = ReadCauses.Step(x?.ErrorStage ?? ((n.Flags & NodeFlags.ListFailed) != 0 ? "list" : null));
            var err = code != 0 ? $" (error {code}: {Win32Message(code)})" : "";
            var f = new Finding
            {
                Node = n, Category = FindingCategory.Unreadable, Origin = Origin.Unknown, Confidence = Confidence.Documented,
                Cause = cause, Detail = ReadCauses.Label(cause),
                Summary = $"{char.ToUpper(step[0])}{step[1..]} — {ReadCauses.Label(cause)}{err}",
                Explanation = ReadCauses.Explain(cause),
            };
            ApplyQuirkRule(f, S());
            Add(n, f, all);
        }

        // --- permissions -------------------------------------------------------------------
        var sd = _r.SdOf(n);
        if (sd?.Owner is { } owner) OwnerCounts[owner] = OwnerCounts.GetValueOrDefault(owner) + 1;
        if (sd != null && (sd.IsBreakpoint || n.IsRoot))
        {
            foreach (var a in sd.Dacl ?? Enumerable.Empty<AceInfo>())
                if (!a.IsInherited) Ref(a.Sid, n);
            foreach (var a in sd.Sacl ?? Enumerable.Empty<AceInfo>())
                if (!a.IsInherited && !a.IsLabel) Ref(a.Sid, n);

            // Fold: same explicit entries as the parent → part of the parent's decision, not a new one.
            Finding? head = null;
            if (n.Parent != null && _aclHead.TryGetValue(n.Parent, out var parentHead)
                && Signature(n) is { } sig && sig == Signature(n.Parent) && FindPathEntry(S()) == null)
                head = parentHead;
            if (head != null)
            {
                head.Folded++;
                if (n.IsDirectory) _aclHead[n] = head;
            }
            else
            {
                var f = ClassifyAcl(n, sd, S());
                // A per-account layout that names no actual account here (only built-in principals) is plain Stock.
                if (f.Origin == Origin.PerAccount && !NamesAccount(sd)) f.Origin = Origin.Stock;
                Add(n, f, all);
                if (n.IsDirectory && sd.HasExplicitDaclAce) _aclHead[n] = f;
            }
        }

        // --- orphaned SIDs ----------------------------------------------------------------
        if (sd != null) ClassifyOrphans(n, sd, all, S);

        // --- Explorer "Continue" grants ------------------------------------------------------
        if (sd != null && n.IsDirectory)
            foreach (var sid in ExplorerGrantSids(n, sd))
                Add(n, new Finding
                {
                    // Always red: the mark is a standing full-control grant, the most dangerous thing a click can leave behind.
                    Node = n, Category = FindingCategory.ExplorerGrant, Origin = Origin.Modified, Confidence = Confidence.Observed,
                    Detail = sid,
                    Summary = $"{_r.NameOf(sid).Display} has full control here — the exact mark of Explorer's \"Continue\"",
                    Explanation = "When an account opens a folder it cannot read, Explorer offers \"You don't currently have permission to "
                        + "access this folder — Continue to permanently get access\". Confirming with an administrator's password does not "
                        + "let Explorer act as that administrator: it adds the signed-in account to the folder with full control, for this "
                        + "folder, its subfolders and files — permanently. Full control includes changing the permissions and taking "
                        + "ownership. On another account's profile that means its startup folder and scripts can be changed by this "
                        + "account. The grant goes to the account itself, not to Administrators: every unelevated process of this account — "
                        + "browser, mail, anything downloaded — can now open and change this folder; for it, UAC no longer applies. "
                        + "To look into protected folders without leaving this behind, use an elevated file manager or an elevated "
                        + "PowerShell: they open the folder with the administrator's rights already in hand, so there is no prompt and no grant. "
                        + "A deliberate grant set by hand looks the same; if this one is wanted, leave it. "
                        + "Undo: Accounts & groups → this account → \"Undo this account's Explorer grants…\", or "
                        + $"icacls \"{n.FullPath}\" /remove:g *{sid}",
                }, all);

        // --- streams ------------------------------------------------------------------------
        if (n.Extra?.Streams is { } streams)
            foreach (var s in streams)
                Add(n, ClassifyStream(n, s, S()), all);

        // --- reparse ------------------------------------------------------------------------
        if (n.Extra?.Reparse is { } rp)
            Add(n, ClassifyReparse(n, rp, S()), all);

        // --- other quirks -------------------------------------------------------------------
        var attr = (FileAttributes)n.Attributes;
        if (!n.IsDirectory && n.LinkCount > 1)
            Add(n, Quirk(n, FindingCategory.HardLink, $"{n.LinkCount} names point to this file", S()), all);
        if ((n.Flags & NodeFlags.CaseSensitive) != 0)
            Add(n, Quirk(n, FindingCategory.CaseSensitive, "Directory is case-sensitive", S()), all);
        if ((attr & FileAttributes.Encrypted) != 0)
            Add(n, Quirk(n, FindingCategory.Encrypted, "EFS encrypted", S()), all);
        if ((attr & FileAttributes.Compressed) != 0 && (n.Parent == null || ((FileAttributes)n.Parent.Attributes & FileAttributes.Compressed) == 0))
            Add(n, Quirk(n, FindingCategory.Compressed, n.IsDirectory ? "NTFS compression enabled on folder" : "NTFS compressed", S()), all);
        if ((attr & FileAttributes.SparseFile) != 0)
            Add(n, Quirk(n, FindingCategory.Sparse, "Sparse file", S()), all);
        if (n.Extra?.ObjectId is Guid oid)
            Add(n, Quirk(n, FindingCategory.ObjectId, "Object ID " + oid.ToString("B"), S()), all);
        if (n.Parent != null)
        {
            int len = P().Length;
            if (len > 259 && n.Parent.FullPath.Length <= 259)
                Add(n, Quirk(n, FindingCategory.LongPath, $"Path is {len} characters (limit for classic tools: 259)", S()), all);
        }
    }

    /// <summary>Why this file may be deleted, when its permissions finding comes from a knowledge pattern marked "removable"
    /// (an explained leftover); null otherwise.</summary>
    public (string Explain, string KbId)? RemovableWhy(ScanNode n)
    {
        var f = n.Findings?.FirstOrDefault(x => x.Category == FindingCategory.Acl && x.KbId?.StartsWith("patterns/", StringComparison.Ordinal) == true);
        if (f == null) return null;
        var id = f.KbId!["patterns/".Length..];
        foreach (var (e, _) in _kb.Patterns)
            if (e.Removable && string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(e.Explain))
                return (e.Explain!, f.KbId!);
        return null;
    }

    /// <summary>For an object in Task Scheduler's store (%SystemRoot%\System32\Tasks): the PowerShell line that
    /// unregisters it (a task file) or every task in it (a task folder). Null elsewhere.</summary>
    public static string? TaskCommand(ScanNode n, OsInfo os)
    {
        if (!os.Paths.TryGetValue("SystemRoot", out var sr)) return null;
        var store = sr.TrimEnd('\\') + "\\System32\\Tasks\\";
        var path = n.FullPath;
        if (!path.StartsWith(store, StringComparison.OrdinalIgnoreCase)) return null;
        var rel = path[store.Length..];
        if (n.IsDirectory)
            return $"Get-ScheduledTask -TaskPath '\\{rel}\\' | Unregister-ScheduledTask -Confirm:$false";
        var cut = rel.LastIndexOf('\\');
        var taskPath = cut < 0 ? "\\" : "\\" + rel[..cut] + "\\";
        var name = cut < 0 ? rel : rel[(cut + 1)..];
        return $"Unregister-ScheduledTask -TaskPath '{taskPath}' -TaskName '{name.Replace("'", "''")}' -Confirm:$false";
    }

    /// <summary>User accounts that have Explorer's "Continue" mark on this folder: one explicit allow entry, full
    /// control, this folder + subfolders + files ((OI)(CI), not inherit-only), for an existing user account that does
    /// not own the profile this folder is in. Observed on Windows 11 build 26300: Explorer adds exactly this entry to
    /// the folder clicked and nothing to its children (they inherit it).</summary>
    public IEnumerable<string> ExplorerGrantSids(ScanNode n, SdInfo sd)
    {
        const AceFlags want = AceFlags.ObjectInherit | AceFlags.ContainerInherit;
        const AceFlags inh = AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit;
        foreach (var a in sd.ExplicitDaclAces)
        {
            if (a.IsDeny || a.IsAudit || a.IsLabel || (a.Flags & inh) != want || a.NormalizedMask != 0x1F01FF) continue;
            if (SidText.SplitAccountSid(a.Sid) is not { } split || split.Rid < 1000) continue;
            // The personal certificate store gives its creating account exactly this entry (with SYSTEM, Administrators and
            // the smart-card capability S-1-15-3-9): not Explorer's mark. Another account there is reported by the pattern.
            if (sd.ExplicitDaclAces.Any(x => x.Sid == "S-1-15-3-9")) continue;
            if (_r.NameOf(a.Sid).Use != SidUse.User) continue;
            if (string.Equals(ProfileSidOf(n), a.Sid, StringComparison.OrdinalIgnoreCase)) continue;
            // An account's own recycle bin ($Recycle.Bin\<its SID>) carries exactly this entry by design.
            if (string.Equals(n.Name, a.Sid, StringComparison.OrdinalIgnoreCase)
                && string.Equals(n.Parent?.Name, "$Recycle.Bin", StringComparison.OrdinalIgnoreCase)) continue;
            yield return a.Sid;
        }
    }

    /// <summary>Whether an account SID (S-1-5-21-…) still exists.
    /// Proven: Windows answered "unknown" (error 1332), the SID is from this machine's own account
    /// database, or the machine has no domain that could know it. Unverifiable: the lookup failed for
    /// another reason, e.g. the domain controller could not be reached — such SIDs may be fine.</summary>
    /// <summary>This machine's built-in Administrator (machine SID + -500): its SID differs on every install, so the knowledge
    /// base names it as $LOCALADMIN. Null when the machine SID is not known.</summary>
    private string? LocalAdminSid => string.IsNullOrEmpty(_r.Os.MachineSid) ? null : _r.Os.MachineSid + "-500";

    private HashSet<Guid>? _vmIds;
    private bool _vmIdsRead;

    /// <summary>The IDs of the Hyper-V VMs that exist, as far as this scan can tell: every &lt;VM id&gt;.vmcx found anywhere
    /// (a VM's own configuration, and vmms's cache in %ProgramData%\Microsoft\Windows\Hyper-V\Virtual Machines Cache).
    /// Null when nothing can be said: Hyper-V's store is not in the scan, or not every drive was scanned.</summary>
    private HashSet<Guid>? VmIds()
    {
        if (_vmIdsRead) return _vmIds;
        _vmIdsRead = true;
        bool wholeDrives = _r.Roots.Count > 0 && _r.Roots.All(x => x.Name.TrimEnd('\\').Length == 2 && x.Name[1] == ':');
        if (!wholeDrives) return null;
        var ids = new HashSet<Guid>();
        bool store = false;
        foreach (var n in _r.AllNodes())
        {
            if (n.IsDirectory)
            {
                if (n.Name.Equals("Virtual Machines Cache", StringComparison.OrdinalIgnoreCase)
                    && n.FullPath.EndsWith(@"\Microsoft\Windows\Hyper-V\Virtual Machines Cache", StringComparison.OrdinalIgnoreCase))
                    store = true;
                continue;
            }
            if (n.Name.EndsWith(".vmcx", StringComparison.OrdinalIgnoreCase) && Guid.TryParse(n.Name[..^5], out var id)) ids.Add(id);
        }
        return _vmIds = store ? ids : null;
    }

    /// <summary>The VM ID inside a Hyper-V VM account SID (S-1-5-83-1-a-b-c-d: the GUID's 16 bytes as four RIDs).</summary>
    public static Guid? VmIdOf(string sid)
    {
        if (!sid.StartsWith("S-1-5-83-1-", StringComparison.OrdinalIgnoreCase)) return null;
        var parts = sid[11..].Split('-');
        if (parts.Length != 4) return null;
        var bytes = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            if (!uint.TryParse(parts[i], out var v)) return null;
            BitConverter.GetBytes(v).CopyTo(bytes, i * 4);   // little-endian, as Windows stores the RIDs
        }
        return new Guid(bytes);
    }

    /// <summary>A Hyper-V VM account whose VM no longer exists on this machine (only said after a scan of every drive with
    /// Hyper-V's store in it).</summary>
    public bool IsVmGone(string sid) => VmIdOf(sid) is { } id && VmIds() is { } ids && !ids.Contains(id);

    public OrphanState OrphanStateOf(string? sid)
    {
        if (string.IsNullOrEmpty(sid) || SidText.SplitAccountSid(sid) is not { } split) return OrphanState.None;
        // SIDs the knowledge base knows (e.g. the image-build machine's accounts baked into Windows media) are stock.
        if (_kb.Principal(sid) != null) return OrphanState.None;
        var p = _r.NameOf(sid);
        if (p.Resolved) return p.Use == SidUse.DeletedAccount ? OrphanState.Proven : OrphanState.None;
        if (p.LookupError == 1332) return OrphanState.Proven;
        if (string.Equals(split.Prefix, _r.Os.MachineSid, StringComparison.OrdinalIgnoreCase)) return OrphanState.Proven;
        if (!_r.Os.DomainJoined) return OrphanState.Proven;
        return OrphanState.Unverifiable;
    }

    private void ClassifyOrphans(ScanNode n, SdInfo sd, List<Finding> all, Func<string[]> segs)
    {
        var proven = new List<string>();
        var unverifiable = new List<string>();
        void Note(string? sid, string what)
        {
            switch (OrphanStateOf(sid))
            {
                case OrphanState.Proven: proven.Add(what); break;
                case OrphanState.Unverifiable: unverifiable.Add(what); break;
            }
        }
        var parentOwner = n.Parent != null ? _r.SdOf(n.Parent)?.Owner : null;
        if (!string.Equals(parentOwner, sd.Owner, StringComparison.OrdinalIgnoreCase)) Note(sd.Owner, "owner " + sd.Owner);
        foreach (var a in sd.Dacl ?? Enumerable.Empty<AceInfo>())
            if (!a.IsInherited) Note(a.Sid, $"{a.TypeName.ToLowerInvariant()} entry for {a.Sid}");
        foreach (var a in sd.AuditAces)
            if (!a.IsInherited) Note(a.Sid, $"audit entry for {a.Sid}");

        // The exact shape of Explorer's "Continue" mark for an account that no longer exists (ExplorerGrantSids only names living accounts).
        bool explorerShaped = n.IsDirectory && (sd.Dacl ?? Enumerable.Empty<AceInfo>()).Any(a =>
            !a.IsInherited && !a.IsDeny && !a.IsAudit && !a.IsLabel && a.NormalizedMask == 0x1F01FF
            && (a.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit | AceFlags.InheritOnly | AceFlags.NoPropagateInherit)) == (AceFlags.ObjectInherit | AceFlags.ContainerInherit)
            && SidText.SplitAccountSid(a.Sid) is { Rid: >= 1000 } && OrphanStateOf(a.Sid) == OrphanState.Proven);
        if (proven.Count > 0)
        {
            var f = new Finding
            {
                Node = n, Category = FindingCategory.Orphan, Origin = Origin.Custom, Confidence = Confidence.Documented, Detail = "proven",
                Summary = "Account no longer exists: " + string.Join("; ", proven.Distinct()),
                Explanation = "Windows confirms these SIDs belong to no existing account — typically a deleted local user, a removed group, "
                              + "an account from an earlier Windows installation, or from a machine this disk came from. "
                              + "Entries for them grant nothing to anyone now; they are leftovers of earlier setup.",
            };
            if (TaskCommand(n, _r.Os) is { } cmd)
                f.Explanation = "This is a scheduled task" + (n.IsDirectory ? " folder" : "") + " in Task Scheduler's store that "
                    + "names a deleted account. Files here are task definitions: remove the task through Task Scheduler, not as a "
                    + "file, so its registry cache goes too. Check first that it is not shared with a living account "
                    + "(Get-ScheduledTask … | Select-Object -ExpandProperty Principal):\n" + cmd + "\n\n" + f.Explanation;
            if (explorerShaped && TaskCommand(n, _r.Os) == null)
                f.Explanation += " The entry has exactly the shape Explorer's \"Continue\" leaves (full control for one account on this "
                    + "folder, its subfolders and files), so this is probably an old Explorer access by an account that is gone. Probably: "
                    + "Windows does not record who clicked, and an entry set by hand looks the same.";
            ApplyQuirkRule(f, segs());
            Add(n, f, all);
        }
        if (unverifiable.Count > 0)
        {
            Add(n, new Finding
            {
                Node = n, Category = FindingCategory.Orphan, Origin = Origin.Unknown, Confidence = Confidence.Documented, Detail = "unverifiable",
                Summary = "Account could not be checked: " + string.Join("; ", unverifiable.Distinct()),
                Explanation = "The name lookup failed for a reason other than \"unknown account\" — usually the domain controller of that "
                              + "domain could not be reached during the scan. The account may well exist; scan again with the domain reachable.",
            }, all);
        }
    }

    /// <summary>The explicit entries that apply to an object, as a comparable key (cached per descriptor).</summary>
    private string? Signature(ScanNode n)
    {
        if (n.SdIndex < 0 || n.SdIndex >= _signatures.Length) return null;
        if (_signatures[n.SdIndex] is { } cached) return cached.Length == 0 ? null : cached;
        var sd = _r.SdOf(n);
        var key = sd == null ? "" : string.Join("|", sd.ExplicitDaclAces.Where(a => !a.IsInheritOnly)
            .Select(a => $"{a.Type}:{a.Sid}:{a.NormalizedMask:x}").Distinct().OrderBy(x => x, StringComparer.Ordinal));
        _signatures[n.SdIndex] = key;
        return key.Length == 0 ? null : key;
    }

    private KbPath? FindPathEntry(string[] segs)
    {
        foreach (var (entry, pattern, _) in _kb.Paths)
            if (pattern.IsMatch(segs)) return entry;
        return null;
    }

    /// <summary>Known stock objects that are absent from a complete scan of their volume. They go to a separate list,
    /// not to the findings: an image built with fewer components leaves them out on purpose, so absence is not judged.</summary>
    private void AddMissingStockItems()
    {
        if (_r.Cancelled) return;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (entry, pattern, _) in _kb.Paths)
        {
            if (!entry.Expected || pattern.LiteralPath is not { } path || !seen.Add(path)) continue;
            // only judge volumes that were scanned from their root
            var root = _r.Roots.FirstOrDefault(r => (r.Flags & NodeFlags.IsVolumeRoot) != 0
                                                    && path.StartsWith(r.Name, StringComparison.OrdinalIgnoreCase));
            if (root == null || _r.FindByPath(path) != null) continue;
            // Report only the topmost absence: if the parent is gone too, that (or its own parent) is the entry.
            var trimmed = path.TrimEnd('\\');
            int cut = trimmed.LastIndexOf('\\');
            if (cut < 0) continue;
            var parentPath = cut <= 2 ? trimmed[..cut] + "\\" : trimmed[..cut];
            var parent = _r.FindByPath(parentPath);
            if (parent == null) continue;
            if (!Listed(parent)) continue;
            _r.NotPresent.Add(new NotPresentItem
            {
                Path = path, Folder = parent.FullPath, KbId = "paths/" + entry.Id, Explain = entry.Explain,
            });
        }
    }

    /// <summary>False (and the folder noted once) when its contents could not be listed: then nothing below it can be
    /// said to be absent.</summary>
    private bool Listed(ScanNode folder)
    {
        if ((folder.Flags & NodeFlags.ListFailed) == 0) return true;
        if (!_r.NotPresentUnlisted.Contains(folder.FullPath, StringComparer.OrdinalIgnoreCase)) _r.NotPresentUnlisted.Add(folder.FullPath);
        return false;
    }

    private void Ref(string sid, ScanNode n)
    {
        if (string.IsNullOrEmpty(sid)) return;
        if (!ExplicitRefs.TryGetValue(sid, out var list)) ExplicitRefs[sid] = list = new List<ScanNode>();
        if (list.Count == 0 || list[^1] != n) list.Add(n);
    }

    // ---- ACL ------------------------------------------------------------------------------

    private Finding ClassifyAcl(ScanNode n, SdInfo sd, string[] segs)
    {
        var f = new Finding { Node = n, Category = FindingCategory.Acl, Summary = AclSummary(sd) };

        if (sd.ParseError != null)
        {
            f.Origin = Origin.Unknown; f.Confidence = Confidence.Documented;
            f.Explanation = "The security descriptor could not be parsed: " + sd.ParseError;
            return f;
        }

        // 1. known location
        foreach (var (entry, pattern, aces) in _kb.Paths)
        {
            if (!pattern.IsMatch(segs)) continue;
            if (entry.Kind == "dir" && !n.IsDirectory || entry.Kind == "file" && n.IsDirectory) continue;
            // A profile folder no living account uses is a leftover, not a modified profile.
            if (aces != null && aces.Any(a => a.Principal == "$PROFILE") && n.IsDirectory && n.Extra?.Reparse == null
                && (ProfileSidOf(n) is not { } psid || OrphanStateOf(psid) == OrphanState.Proven))
                return LeftoverProfile(n, f, ProfileSidOf(n));
            f.KbId = "paths/" + entry.Id;
            f.Confidence = entry.ConfidenceValue;
            f.Explanation = entry.Explain ?? "";
            if (aces == null)
            {
                f.Origin = entry.OriginValue;
                f.Confidence = Confidence.Unverified;
                f.Explanation += (f.Explanation.Length > 0 ? " " : "") + "(Known location — its ACL is not yet compared against a reference.)";
                return f;
            }
            var diffs = Compare(n, sd, entry.Mode, entry.Protected, entry.Owner, aces, out bool raises);
            if (diffs.Count == 0) { f.Origin = entry.OriginValue; return f; }
            foreach (var v in entry.Variants ?? new List<KbVariant>())
            {
                if (v.Parsed == null) continue;
                if (Compare(n, sd, v.Mode ?? entry.Mode, v.Protected ?? entry.Protected, v.Owner ?? entry.Owner, v.Parsed, out _).Count > 0) continue;
                f.Origin = entry.OriginValue;
                f.Detail = "known variant";
                f.Explanation = $"Matches a known variant: {v.Label}. " + (v.Explain != null ? v.Explain + " " : "")
                                + "The reference install has a different ACL here:\n" + string.Join("\n", diffs.Select(d => "• " + d))
                                + "\n\n" + f.Explanation;
                return f;
            }
            f.Differences = diffs;
            if (raises || entry.OriginValue != Origin.Stock)
            {
                f.Origin = Origin.Modified;
                f.BroadDeny = sd.ExplicitDaclAces.Any(Rights.IsBroadDeny);
                return f;
            }
            f.Origin = Origin.Differs;
            f.Explanation = "Differs from the fresh reference install, but only in ways that give no one more control: read or list "
                            + "rights, or which system account (SYSTEM, Administrators, TrustedInstaller) holds a right or owns the object. "
                            + "Windows writes such ACLs when a component sets itself up, and another build or an update writes them "
                            + "slightly differently; an in-place upgrade keeps existing ACLs. Who wrote this one, and when, is not recorded "
                            + "by Windows.\n\n" + f.Explanation;
            return f;
        }

        // 2. pattern rules
        var explicitAces = sd.ExplicitDaclAces.ToList();
        foreach (var (entry, under) in _kb.Patterns)
        {
            if (!CompiledKb.UnderMatches(under, segs)) continue;
            // A rule for any location (no "under") speaks only about explicit entries; without any it says nothing.
            if (under == null && explicitAces.Count == 0) continue;
            if (entry.Protected is bool prot && prot != sd.DaclProtected) continue;
            if (entry.Owners is { Count: > 0 } owners && (sd.Owner == null || !owners.Any(o => SidMatches(o, sd.Owner)))) continue;
            if (entry.Principals is { Count: > 0 } allowed && !explicitAces.All(a => allowed.Any(p => PrincipalToken(p, a.Sid, n, sd)))) continue;
            f.KbId = "patterns/" + entry.Id;
            f.Origin = entry.OriginValue;
            f.Confidence = entry.ConfidenceValue;
            f.Explanation = entry.Explain ?? "";
            return f;
        }

        // 3. fallback: judge by the principals involved
        var foreign = explicitAces.Select(a => a.Sid).Concat(sd.AuditAces.Where(a => !a.IsInherited).Select(a => a.Sid))
            .Distinct().Where(s => !IsBuiltinPrincipal(s)).ToList();
        var broadDeny = explicitAces.Where(Rights.IsBroadDeny).Select(a => _r.NameOf(a.Sid).Display).Distinct().ToList();
        f.BroadDeny = broadDeny.Count > 0;
        const string broadDenyText = "Windows sets these only in a few known places (such as the legacy junctions in profiles); "
                                     + "elsewhere it is usually set by hand or by a hardening tool.";
        if (n.IsRoot && !sd.IsBreakpoint)
        {
            f.Origin = Origin.Unknown;
            f.Explanation = "Scan root. Its permissions are shown for reference.";
        }
        else if (foreign.Count > 0)
        {
            f.Origin = Origin.Custom;
            f.Confidence = Confidence.Assumed;
            f.Explanation = "Explicit permissions for accounts or groups that Windows does not create itself: "
                            + string.Join(", ", foreign.Select(s => _r.NameOf(s).Display)) + ". "
                            + "These were set by an administrator, an installer or an application."
                            + (broadDeny.Count > 0 ? $" It also holds an explicit Deny for {string.Join(", ", broadDeny)}. " + broadDenyText : "");
        }
        else if (broadDeny.Count > 0)
        {
            f.Origin = Origin.Custom;
            f.Confidence = Confidence.Assumed;
            f.Explanation = $"An explicit Deny for a broad group: {string.Join(", ", broadDeny)}. " + broadDenyText;
        }
        else if (n.IsRoot || _kb.InSystemArea(segs))
        {
            f.Origin = Origin.Unknown;
            f.Confidence = Confidence.Assumed;
            f.Explanation = "Only Windows built-in principals are involved, but this location is not in the knowledge base. "
                            + "It may be stock (set by Windows or a Windows feature) or set by an installer. "
                            + "Copy it for AI to help fill the gap.";
        }
        else
        {
            f.Origin = Origin.Custom;
            f.Confidence = Confidence.Assumed;
            f.Explanation = "Explicit entries that Windows does not set here: this is outside the areas Windows manages itself, "
                            + "so they were set by hand or by an application (or are left from an earlier installation).";
        }
        return f;
    }

    /// <summary>A pattern principal: a SID, alias or glob, or a token resolved per object —
    /// $OWNER (the object's owner), $PROFILE (the account owning the profile the object is in), $ANYPROFILE (any account in
    /// Windows' profile list), $NAMESID (an account SID written in the object's path, e.g. a per-account task or folder),
    /// $FILENAME (the account whose name is the file's name without extension), $ORPHAN (a proven orphaned account).</summary>
    private bool PrincipalToken(string p, string sid, ScanNode n, SdInfo sd) => p switch
    {
        "$OWNER" => string.Equals(sid, sd.Owner, StringComparison.OrdinalIgnoreCase),
        "$PROFILE" => string.Equals(sid, ProfileSidOf(n), StringComparison.OrdinalIgnoreCase),
        "$ANYPROFILE" => _r.Os.Profiles.ContainsKey(sid),
        "$NAMESID" => sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && n.FullPath.Contains(sid, StringComparison.OrdinalIgnoreCase),
        "$FILENAME" => _r.NameOf(sid) is { Resolved: true } pn && pn.Use == SidUse.User
                       && string.Equals(pn.Name, System.IO.Path.GetFileNameWithoutExtension(n.Name), StringComparison.OrdinalIgnoreCase),
        "$ORPHAN" => OrphanStateOf(sid) == OrphanState.Proven,
        "$VMGONE" => IsVmGone(sid),
        "$LOCALADMIN" => string.Equals(sid, LocalAdminSid, StringComparison.OrdinalIgnoreCase),
        _ => SidMatches(p, sid),
    };

    private bool SidMatches(string pattern, string sid)
    {
        var p = Kb.ResolveAlias(pattern);
        return p.Contains('*') ? Kb.Glob(p, sid) : string.Equals(p, sid, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsBuiltinPrincipal(string sid)
    {
        var p = _kb.Principal(sid);
        if (p != null) return p.Builtin;
        // account-domain RIDs below 1000 are created by Windows (Administrator, Guest, ...)
        if (SidText.SplitAccountSid(sid) is { } split) return split.Rid < 1000;
        return false;
    }

    /// <summary>The SID a knowledge-base principal stands for on this object: $OWNER = its owner; $PROFILE = the
    /// account Windows' profile list assigns to the profile folder this object is (or is in); cap:name = the
    /// capability SID of that name (as derived on this machine or stored in the snapshot).</summary>
    public string? ResolvePrincipal(AceSpec s, ScanNode n, SdInfo sd)
    {
        if (s.Principal == "$OWNER") return sd.Owner;
        if (s.Principal == "$PROFILE") return ProfileSidOf(n);
        if (s.Principal == "$LOCALADMIN") return LocalAdminSid;
        if (s.Principal.StartsWith("cap:", StringComparison.OrdinalIgnoreCase))
        {
            var name = s.Principal[4..];
            foreach (var p in _r.Names.Values)
                if (p.Domain == "Capability" && string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) return p.Sid;
            return null;
        }
        return s.Principal;
    }

    private Finding LeftoverProfile(ScanNode n, Finding f, string? sid)
    {
        f.Origin = Origin.Trace;
        f.Confidence = Confidence.Documented;
        f.KbId = "paths/profile-folder";
        f.Detail = "leftover profile";
        f.Summary = (sid != null ? $"Leftover profile of a deleted account ({sid})" : "Leftover profile folder — not in Windows' profile list")
                    + " · " + AclSummary(_r.SdOf(n)!);
        f.Explanation = sid != null
            ? "Windows' profile list still names this folder, but its account no longer exists, so nothing uses it. Remove both "
              + "the folder and the list entry with Accounts & groups → this SID → \"Clean up this SID…\", or by hand:\n"
              + $"Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}' | Remove-CimInstance"
            : "No account in Windows' profile list uses this folder. It is left over from an account deleted earlier (or a "
              + "copy); nothing reads it. It can be deleted by hand once you have checked it holds nothing you want.";
        return f;
    }

    /// <summary>The account whose profile folder holds this object, from Windows' profile list (null when the
    /// object is in no listed profile).</summary>
    public string? ProfileSidOf(ScanNode n)
    {
        var path = n.FullPath;
        foreach (var (sid, dir) in _r.Os.Profiles)
            if (path.Equals(dir, StringComparison.OrdinalIgnoreCase) || path.StartsWith(dir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                return sid;
        return null;
    }

    /// <summary>Accounts whose rights count as the system's own: moving rights or ownership between them gives no one more control.</summary>
    public static bool IsSystemPrincipal(string? sid) =>
        sid is "S-1-5-18" or "S-1-5-32-544" || string.Equals(sid, Kb.TrustedInstaller, StringComparison.OrdinalIgnoreCase);

    /// <summary>Rights that let someone change what is there: write/append data (create files/folders), delete, delete
    /// children, change permissions, take ownership. Read, list, execute and attribute rights are not in it.</summary>
    public const uint ControlRights = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000;

    /// <summary>True when the owner or an explicit entry is a local or domain account (RID 1000 and up).</summary>
    private static bool NamesAccount(SdInfo sd) =>
        (sd.Owner != null && SidText.SplitAccountSid(sd.Owner) is { Rid: >= 1000 })
        || sd.ExplicitDaclAces.Any(x => SidText.SplitAccountSid(x.Sid) is { Rid: >= 1000 });

    /// <summary>An account of another machine's account database (not this machine's, and this machine has no domain):
    /// it can never sign in here, so an entry for it neither grants nor denies anything — e.g. the image-build accounts.</summary>
    public bool IsForeignAccount(string? sid)
    {
        if (sid == null || SidText.SplitAccountSid(sid) is not { } split) return false;
        if (_r.Os.DomainJoined) return false;
        return _r.Os.MachineSid == null || !string.Equals(split.Prefix, _r.Os.MachineSid, StringComparison.OrdinalIgnoreCase);
    }

    /// <param name="raises">True when a difference gives someone more control: an extra allow with control rights for
    /// an account other than SYSTEM/Administrators/TrustedInstaller, a missing deny that could apply on this machine,
    /// protection removed, or an owner other than those three.</param>
    private List<string> Compare(ScanNode n, SdInfo sd, string? mode, bool? protectedWanted, string? ownerWanted, List<AceSpec> specs, out bool raises)
    {
        raises = false;
        var diffs = new List<string>();
        var actual = sd.ExplicitDaclAces.ToList();
        var used = new bool[actual.Count];
        foreach (var spec in specs.Where(s => !s.Audit))
        {
            int hit = -1;
            for (int i = 0; i < actual.Count; i++)
                if (!used[i] && spec.Matches(actual[i], ResolvePrincipal(spec, n, sd))) { hit = i; break; }
            if (hit >= 0) used[hit] = true;
            else if (!spec.Optional)
            {
                var who = ResolvePrincipal(spec, n, sd);
                bool foreign = spec.Deny && IsForeignAccount(who);
                diffs.Add("Missing: " + DescribeSpec(spec, who) + (foreign ? " — an account of another machine: this deny never applied here" : ""));
                if (spec.Deny && !foreign) raises = true;
            }
        }
        bool exact = !string.Equals(mode, "contains", StringComparison.OrdinalIgnoreCase);
        if (exact)
            for (int i = 0; i < actual.Count; i++)
                if (!used[i])
                {
                    var a = actual[i];
                    diffs.Add("Additional: " + DescribeAce(a, true));
                    if (!a.IsDeny && !a.IsAudit && !IsSystemPrincipal(a.Sid) && (a.NormalizedMask & ControlRights) != 0) raises = true;
                }
        if (protectedWanted is bool prot && prot != sd.DaclProtected)
        {
            diffs.Add(prot ? "Inheritance is enabled, expected disabled (protected)" : "Inheritance is disabled (protected), expected enabled");
            if (prot) raises = true;
        }
        if (!string.IsNullOrEmpty(ownerWanted) && sd.Owner != null && !SidMatches(ownerWanted, sd.Owner))
        {
            diffs.Add($"Owner is {_r.NameOf(sd.Owner).Display}, expected {_r.NameOf(Kb.ResolveAlias(ownerWanted)).Display}");
            if (!IsSystemPrincipal(sd.Owner)) raises = true;
        }
        return diffs;
    }

    private string DescribeSpec(AceSpec s, string? resolved)
    {
        var name = resolved != null ? NameWithKb(resolved) : s.Principal;
        if (s.Principal == "$OWNER") name += " (owner)";
        if (s.Principal == "$PROFILE") name = resolved != null ? name + " (profile account)" : "the profile's account (not in Windows' profile list)";
        if (s.Principal == "$LOCALADMIN") name = resolved != null ? name + " (this machine's built-in Administrator)" : "this machine's built-in Administrator";
        return $"{(s.Audit ? "Audit" : s.Deny ? "Deny" : "Allow")} {name} {Rights.Short(s.Mask)} {Rights.InheritShort(s.Inherit)}".TrimEnd();
    }

    public string DescribeAce(AceInfo a, bool isDirectory) =>
        $"{a.TypeName} {NameWithKb(a.Sid)} {Rights.Short(a.Mask)} {Rights.InheritShort(a.Flags)}".TrimEnd();

    /// <summary>Windows' name for a SID, or the knowledge base's name with the SID when Windows has none
    /// ("image-build Guest (S-1-5-21-…-501)").</summary>
    public string NameWithKb(string sid)
    {
        var p = _r.NameOf(sid);
        if (p.Resolved) return p.Display;
        return _kb.Principal(sid) is { Name: { } kbName } ? $"{kbName} ({sid})" : p.Display;
    }

    private string AclSummary(SdInfo sd)
    {
        var parts = new List<string>();
        if (sd.NullDacl) parts.Add("NULL DACL — no access control at all");
        if (sd.DaclProtected) parts.Add("inheritance disabled");
        int explicitCount = sd.ExplicitDaclAces.Count();
        if (explicitCount > 0)
            parts.Add($"{explicitCount} explicit: " + string.Join(", ", sd.ExplicitDaclAces.Take(4).Select(a =>
                $"{(a.IsDeny ? "DENY " : "")}{ShortName(a.Sid)} {Rights.Short(a.Mask)}")) + (explicitCount > 4 ? ", …" : ""));
        if (sd.HasExplicitSaclAce) parts.Add("explicit auditing");
        if (sd.HasExplicitLabel && sd.Label is { } l) parts.Add($"integrity label {Rights.LabelLevel(l.Sid)}");
        if (parts.Count == 0) parts.Add("inherits only");
        return string.Join("; ", parts);
    }

    private string ShortName(string sid)
    {
        var p = _r.NameOf(sid);
        return p.Resolved ? p.Name! : sid;
    }

    // ---- streams / reparse / quirks -------------------------------------------------------

    private Finding ClassifyStream(ScanNode n, StreamEntry s, string[] segs)
    {
        var f = new Finding
        {
            Node = n, Category = FindingCategory.Stream, Origin = Origin.Unknown, Confidence = Confidence.Assumed,
            Summary = $"Stream \"{s.Name}\" ({s.Size:N0} bytes)",
            Explanation = "A named data stream that is not in the knowledge base. Applications can hide arbitrary data here; it does not show in Explorer or in the file size.",
        };
        (KbStream E, int Score)? best = null;
        foreach (var (e, under) in _kb.Streams)
        {
            if (!Kb.Glob(e.Name, s.Name)) continue;
            int score = CompiledKb.UnderScore(under, segs);
            if (score < 0) continue;
            if (best == null || score > best.Value.Score) best = (e, score);
        }
        if (best is { } b)
        {
            f.KbId = "streams/" + b.E.Id; f.Origin = b.E.OriginValue; f.Confidence = b.E.ConfidenceValue; f.Explanation = b.E.Explain ?? "";
        }
        return f;
    }

    private Finding ClassifyReparse(ScanNode n, ReparseInfo rp, string[] segs)
    {
        var tag = _kb.Tag(rp.Tag);
        var tagName = tag?.Name ?? $"Reparse tag 0x{rp.Tag:X8}";
        bool link = n.IsLink;
        var f = new Finding
        {
            Node = n, Category = link ? FindingCategory.Link : FindingCategory.Reparse,
            Detail = link ? (rp.Tag == 0xA000000C ? "symbolic link" : "junction") : null,
            Summary = tagName + (rp.Target != null ? " → " + rp.Target : ""),
            Origin = tag?.OriginValue ?? Origin.Unknown,
            Confidence = tag?.ConfidenceValue ?? Confidence.Assumed,
            Explanation = tag?.Explain ?? "A reparse tag that is not in the knowledge base; a file system filter driver owns it.",
            KbId = tag != null ? "reparseTags/" + tag.Id : null,
        };
        if (rp.Tag == 0) { f.Summary = "Reparse point (data could not be read)"; f.Origin = Origin.Unknown; }
        bool matched = false;
        foreach (var (e, pattern) in _kb.ReparsePoints)
        {
            if (!pattern.IsMatch(segs)) continue;
            if (!string.IsNullOrEmpty(e.Tag) && !TagMatches(e.Tag, rp.Tag)) continue;
            matched = true;
            f.KbId = "reparsePoints/" + e.Id;
            f.Origin = e.OriginValue;
            f.Confidence = e.ConfidenceValue;
            f.Explanation = (e.Explain ?? "") + (tag?.Explain != null ? "\n\n" + tag.Explain : "");
            if (e.Target != null && n.Parent != null
                && PathPattern.ExpandTarget(e.Target, n.Parent.FullPath, _r.Os) is { } expected)
            {
                var actual = rp.Target != null ? PathPattern.Normalize(rp.Target) : null;
                if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                {
                    f.Origin = Origin.Modified;
                    f.Differences = new List<string> { $"Target: expected {expected}, found {actual ?? "(none)"}" };
                    f.Summary += $" (Windows points it to {expected})";
                    f.Explanation = "This link is one Windows creates, but it points somewhere else now — it was redirected "
                                    + "by a user, a script or a program.\n\n" + f.Explanation;
                }
            }
            break;
        }
        if (link && !matched)
        {
            bool system = _kb.InSystemArea(segs);
            f.Origin = system ? Origin.Unknown : Origin.Custom;
            f.Confidence = Confidence.Assumed;
            f.Explanation = (system
                    ? "A link inside an area Windows manages that is not one of the links Windows is known to create. "
                      + "A component or program may have added it; check its target."
                    : "A link that is not one of the links Windows creates — made by you, a script or a program (mklink, "
                      + "an installer, a sync or dev tool). Everything that opens this path actually reaches the target.")
                + (tag?.Explain != null ? "\n\n" + tag.Explain : "");
        }
        return f;
    }

    /// <summary>Known stock links that are absent from a complete scan of their volume. Listed apart with the items that are
    /// not present, never as findings: deleting the compatibility links is a legitimate choice.</summary>
    private void AddMissingStockLinks()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (entry, pattern) in _kb.ReparsePoints)
        {
            if (!entry.Expected) continue;
            var segs = pattern.Segments;
            if (segs.Count < 2 || segs.Any(x => x == "**")) continue;
            var last = segs[^1];
            if (last.Contains('*') || last.Contains('?')) continue;
            int firstWild = 0;
            while (firstWild < segs.Count - 1 && !segs[firstWild].Contains('*') && !segs[firstWild].Contains('?')) firstWild++;
            var prefix = segs.Take(firstWild).ToArray();
            var prefixPath = prefix.Length == 1 ? prefix[0] + "\\" : string.Join("\\", prefix);
            var root = _r.Roots.FirstOrDefault(r => (r.Flags & NodeFlags.IsVolumeRoot) != 0
                                                    && prefixPath.StartsWith(r.Name.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
            if (root == null || _r.FindByPath(prefixPath) is not { } start) continue;

            var parents = new List<ScanNode> { start };
            for (int i = firstWild; i < segs.Count - 1 && parents.Count > 0; i++)
            {
                var seg = segs[i];
                bool wild = seg.Contains('*') || seg.Contains('?');
                var next = new List<ScanNode>();
                foreach (var p in parents)
                {
                    if (!Listed(p)) continue;
                    foreach (var c in p.Children ?? Enumerable.Empty<ScanNode>())
                    {
                        if (!c.IsDirectory || c.Extra?.Reparse != null || !Kb.Glob(seg, c.Name)) continue;
                        // "*" right under the profiles folder means a real profile (it holds NTUSER.DAT),
                        // so Public and other non-profile folders are not expected to carry these links.
                        if (wild && p.Parent != null && IsProfilesDir(p) && c.Children?.Any(x => x.Name.Equals("NTUSER.DAT", StringComparison.OrdinalIgnoreCase)) != true)
                            continue;
                        next.Add(c);
                    }
                }
                parents = next;
            }
            foreach (var parent in parents)
            {
                if (!Listed(parent)) continue;
                if (parent.Children?.Any(c => c.Name.Equals(last, StringComparison.OrdinalIgnoreCase)) == true) continue;
                var path = parent.FullPath.TrimEnd('\\') + "\\" + last;
                if (!seen.Add(path)) continue;
                var target = entry.Target != null ? PathPattern.ExpandTarget(entry.Target, parent.FullPath, _r.Os) : null;
                _r.NotPresent.Add(new NotPresentItem
                {
                    Path = path, Folder = parent.FullPath, IsLink = true, Target = target,
                    KbId = "reparsePoints/" + entry.Id, Explain = entry.Explain,
                });
            }
        }
    }

    private bool IsProfilesDir(ScanNode n) =>
        _r.Os.Paths.TryGetValue("ProfilesDir", out var pd) && string.Equals(n.FullPath.TrimEnd('\\'), pd.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    private static bool TagMatches(string spec, uint tag) => spec.ToLowerInvariant() switch
    {
        "junction" or "mountpoint" => tag == 0xA0000003,
        "symlink" => tag == 0xA000000C,
        "appexeclink" => tag == 0x8000001B,
        _ => uint.TryParse(spec.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? spec[2..] : spec,
                System.Globalization.NumberStyles.HexNumber, null, out var t) && t == tag,
    };

    private Finding Quirk(ScanNode n, FindingCategory cat, string summary, string[] segs)
    {
        var f = new Finding { Node = n, Category = cat, Summary = summary, Origin = Origin.Unknown, Confidence = Confidence.Assumed };
        ApplyQuirkRule(f, segs);
        return f;
    }

    private void ApplyQuirkRule(Finding f, string[] segs)
    {
        var cat = f.Category.ToString();
        (KbQuirk E, int Score)? best = null;
        foreach (var (e, under) in _kb.Quirks)
        {
            if (!string.Equals(e.Category, cat, StringComparison.OrdinalIgnoreCase)) continue;
            int score = CompiledKb.UnderScore(under, segs);
            if (score < 0) continue;
            if (best == null || score > best.Value.Score) best = (e, score);
        }
        if (best is { } b)
        {
            f.KbId = "quirks/" + b.E.Id;
            f.Origin = Kb.ParseOrigin(b.E.Origin, f.Origin);
            f.Confidence = b.E.ConfidenceValue;
            if (!string.IsNullOrEmpty(b.E.Explain))
                f.Explanation = string.IsNullOrEmpty(f.Explanation) ? b.E.Explain : b.E.Explain + "\n\n" + f.Explanation;
        }
    }

    // ---- inventory ------------------------------------------------------------------------

    public (Origin Origin, string Explain, string? KbId, Confidence Confidence) ClassifyShare(ShareEntry s)
    {
        foreach (var e in _kb.Kb.Doc.Shares)
            if (Kb.OsMatches(e, _r.Os) && Kb.Glob(e.Name, s.Name))
                return (e.OriginValue, e.Explain ?? "", "shares/" + e.Id, e.ConfidenceValue);
        return (Origin.Custom, "A share created after installation by an administrator, a role or an application.", null, Confidence.Assumed);
    }

    public (Origin Origin, string Explain, string? KbId) ClassifyAccount(string? name, string? sid)
    {
        uint? rid = sid != null && SidText.SplitAccountSid(sid) is { } sp ? sp.Rid : null;
        foreach (var e in _kb.Kb.Doc.Accounts)
        {
            if (!Kb.OsMatches(e, _r.Os)) continue;
            if (e.Rid is int r && rid == (uint)r) return (e.OriginValue, e.Explain ?? "", "accounts/" + e.Id);
            if (e.Name != null && name != null && Kb.Glob(e.Name, name)) return (e.OriginValue, e.Explain ?? "", "accounts/" + e.Id);
        }
        if (sid != null)
        {
            var p = _kb.Principal(sid);
            if (p != null) return (p.Builtin ? Origin.Stock : Origin.Custom, p.Explain ?? "", "principals/" + p.Id);
        }
        return (Origin.Custom, "Created after installation.", null);
    }

    public KbPrincipal? PrincipalEntry(string sid) => _kb.Principal(sid);

    public static string Win32Message(int code)
    {
        try { return new Win32Exception(code).Message; } catch { return ""; }
    }
}
