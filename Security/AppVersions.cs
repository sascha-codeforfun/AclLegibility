using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using AclLegibility.Model;
using AclLegibility.Native;

namespace AclLegibility.Security;

/// <summary>What Windows says about one older package version.</summary>
public enum AppVersionState
{
    /// <summary>An account, a dependent app, provisioning or Windows' non-removable flag still needs it.</summary>
    Used,
    /// <summary>Windows lists it, but no existing account uses it and no app depends on it.</summary>
    Unused,
    /// <summary>Windows lists no package by this name: the folder is left over.</summary>
    NotKnown,
}

/// <summary>One package folder in WindowsApps with a newer version of the same package beside it.</summary>
public sealed class AppVersionItem
{
    public required string Folder { get; init; }
    /// <summary>The folder name, which is the package's full name.</summary>
    public required string FullName { get; init; }
    public required string Package { get; init; }
    public required Version Version { get; init; }
    public required Version Newest { get; init; }
    public AppVersionState State { get; set; }
    /// <summary>Why, in plain words, from what Windows answered.</summary>
    public string Reason { get; set; } = "";
    public long Bytes { get; set; }
    public int Objects { get; set; }
    /// <summary>For an unused version: Windows has it staged for the system only (S-1-5-18), installed for no account.
    /// Remove-AppxPackage -AllUsers from an administrator does not take those; a removal as SYSTEM does.</summary>
    public bool StagedOnly { get; set; }
}

public sealed class AppVersionsPlan
{
    public required string WindowsApps { get; init; }
    public List<AppVersionItem> Items { get; } = new();
    /// <summary>How many packages Windows listed (all versions, all accounts).</summary>
    public int Listed { get; set; }
    /// <summary>Anything Windows could not answer (shown in the preview).</summary>
    public List<string> Notes { get; } = new();
    /// <summary>Accounts that no longer exist but that Windows still reports packages as installed for (SID → package
    /// full names), across all packages, not only older versions. Windows offers no removal for a deleted account.</summary>
    public SortedDictionary<string, List<string>> Ghosts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public IEnumerable<AppVersionItem> Used => Items.Where(i => i.State == AppVersionState.Used);
    public IEnumerable<AppVersionItem> Unused => Items.Where(i => i.State == AppVersionState.Unused);
    public IEnumerable<AppVersionItem> Staged => Unused.Where(i => i.StagedOnly);
    public IEnumerable<AppVersionItem> DeletedOnly => Unused.Where(i => !i.StagedOnly);
    public IEnumerable<AppVersionItem> NotKnown => Items.Where(i => i.State == AppVersionState.NotKnown);
}

/// <summary>How a version was handled.</summary>
public enum AppRoute { AsSystem, AllUsers, DeleteFolder }

/// <summary>One version after the run: the way it went, what Windows answered, and what the check found.</summary>
/// <param name="Answer">Windows' answer to the removal in plain words ("OK", or the error translated).</param>
/// <param name="Full">Windows' full text, when it said more than OK.</param>
/// <param name="Status">What the check afterwards found, in plain words.</param>
public sealed record AppVersionResult(AppVersionItem Item, AppRoute Route, string Answer, string? Full, string Status, bool Gone)
{
    public string RouteText => Route switch
    {
        AppRoute.AsSystem => "as SYSTEM",
        AppRoute.AllUsers => "with -AllUsers",
        _ => "folder deleted by the app",
    };
}

/// <summary>What happened, as checked afterwards — never taken from the removal's own answer.</summary>
/// <param name="Gone">Windows no longer lists the version and its folder is gone.</param>
/// <param name="OnDisk">Windows no longer lists it, but its folder is still on disk.</param>
/// <param name="NotRemoved">Windows still lists it.</param>
/// <param name="Checked">False when Windows could not be asked again: then nothing is counted as removed.</param>
public sealed record AppVersionsOutcome(int Gone, int OnDisk, int NotRemoved, int FoldersDeleted, long BytesFreed,
    List<(string What, string Error)> Failed, bool Cancelled, bool Checked, List<AppVersionResult> Results);

/// <summary>
/// The fifth action: older versions of app packages in WindowsApps, which DISM's component clean-up does not touch. The
/// scan cannot tell whether an older version is still needed — only Windows' package manager knows which accounts use it
/// and which apps depend on it — so this asks Windows (Get-AppxPackage -AllUsers, read only) and sorts every older
/// version into used (left alone, with the reason), unused (removed with Windows' own Remove-AppxPackage -AllUsers) and
/// not known to Windows (a leftover folder, deleted after a preview, none ticked by default). Works without a scan.
/// </summary>
public static class AppVersions
{
    private static readonly Regex PackageFolder = new(
        @"^(?<name>[^_]+)_(?<ver>\d+\.\d+\.\d+\.\d+)_(?<arch>x64|x86|arm64|arm|neutral)_(?<res>[^_]*)_(?<pub>[a-z0-9]{13})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SidRx = new(@"S-1-[0-9]+(-[0-9]+)+", RegexOptions.Compiled);

    public static string PowerShellPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    public static string WindowsAppsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");

    /// <summary>Null when it can run; otherwise why not.</summary>
    public static string? WhyNot()
    {
        if (!File.Exists(PowerShellPath)) return "Windows PowerShell (powershell.exe) was not found; Windows' package manager is reached through it.";
        if (!Directory.Exists(WindowsAppsPath)) return "There is no WindowsApps folder on this machine.";
        return null;
    }

    /// <summary>The query sent to Windows. Read only: it lists packages and provisioned packages, nothing else.</summary>
    public const string QueryScript = """
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        try { $pk = Get-AppxPackage -AllUsers -PackageTypeFilter Main,Framework,Resource,Optional,Bundle }
        catch { [Console]::Out.WriteLine("N`tThe package type filter was refused; listed without it: " + $_.Exception.Message); $pk = Get-AppxPackage -AllUsers }
        foreach ($p in $pk) {
          $users = @()
          foreach ($u in @($p.PackageUserInformation)) {
            if ($u -eq $null) { continue }
            $s = $u.UserSecurityId
            $users += ("$($s.Sid) $s" + '=' + $u.InstallState)
          }
          $deps = @($p.Dependencies | ForEach-Object { $_.PackageFullName })
          [Console]::Out.WriteLine("P`t" + $p.PackageFullName + "`t" + $p.IsFramework + "`t" + $p.NonRemovable + "`t" + ($users -join '|') + "`t" + ($deps -join '|'))
        }
        try { foreach ($v in Get-AppxProvisionedPackage -Online) { [Console]::Out.WriteLine("V`t" + $v.PackageName) } }
        catch { [Console]::Out.WriteLine("N`tProvisioned packages could not be listed: " + $_.Exception.Message) }
        """;

    /// <summary>The removal, exactly as run for one package.</summary>
    public static string RemoveScript(string fullName) => $$"""
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        try { Remove-AppxPackage -Package '{{fullName.Replace("'", "''")}}' -AllUsers; [Console]::Out.WriteLine('OK') }
        catch { [Console]::Out.WriteLine('ERR ' + $_.Exception.Message) }
        """;

    public static string RemoveCommand(string fullName) => $"Remove-AppxPackage -Package '{fullName.Replace("'", "''")}' -AllUsers";

    /// <summary>Older versions found in WindowsApps (read from disk now, not from a scan), sorted by what Windows says.</summary>
    public static AppVersionsPlan Plan(Action<string> say, Func<string, (string? Name, bool Deleted)>? account = null)
    {
        account ??= Account;
        Privileges.EnableReadPrivileges();
        var plan = new AppVersionsPlan { WindowsApps = WindowsAppsPath };
        say("Reading " + plan.WindowsApps + "…");
        var probe = new FileProbe(false);
        var entries = new List<DirEntry>();
        int err = probe.ListDirectory(plan.WindowsApps, entries);
        if (err != 0) throw new IOException($"{plan.WindowsApps} could not be listed (error {err}).");
        foreach (var item in Superseded(plan.WindowsApps, entries.Where(e => (e.Attributes & (uint)FileAttributes.Directory) != 0).Select(e => e.Name)))
            plan.Items.Add(item);
        if (plan.Items.Count == 0) return plan;

        say("Asking Windows which accounts and apps use each version (Get-AppxPackage -AllUsers)…");
        var (code, output, error) = RunPowerShell(QueryScript);
        if (code != 0 && !output.Contains("P\t", StringComparison.Ordinal))
            throw new InvalidOperationException("Windows' package manager did not answer: " + (error.Length > 0 ? error : $"exit code {code}"));
        Classify(plan, output, account);

        say("Measuring the older versions…");
        foreach (var i in plan.Items)
        {
            long bytes = 0; int objects = 0;
            Measure(i.Folder, probe, ref bytes, ref objects);
            i.Bytes = bytes; i.Objects = objects;
        }
        return plan;
    }

    /// <summary>Package folders with a newer version of the same package (name, architecture, resource, publisher) beside them.</summary>
    public static List<AppVersionItem> Superseded(string windowsApps, IEnumerable<string> folderNames)
    {
        var groups = new Dictionary<string, List<(string Name, string Package, Version Ver)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in folderNames)
        {
            var m = PackageFolder.Match(name);
            if (!m.Success || !Version.TryParse(m.Groups["ver"].Value, out var v)) continue;
            var key = $"{m.Groups["name"].Value}|{m.Groups["arch"].Value}|{m.Groups["res"].Value}|{m.Groups["pub"].Value}";
            if (!groups.TryGetValue(key, out var list)) groups[key] = list = new();
            list.Add((name, m.Groups["name"].Value, v));
        }
        var result = new List<AppVersionItem>();
        foreach (var list in groups.Values.Where(l => l.Count > 1))
        {
            var newest = list.Max(x => x.Ver)!;
            foreach (var (name, package, ver) in list.Where(x => x.Ver != newest).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                result.Add(new AppVersionItem
                {
                    Folder = Path.Combine(windowsApps, name), FullName = name, Package = package, Version = ver, Newest = newest,
                });
        }
        return result.OrderBy(i => i.Package, StringComparer.OrdinalIgnoreCase).ThenBy(i => i.Version).ToList();
    }

    private sealed class Listed
    {
        public bool IsFramework, NonRemovable;
        public List<(string Sid, string State)> Users = new();
        public List<string> Dependencies = new();
    }

    /// <summary>Sorts the items by Windows' answer (the lines printed by <see cref="QueryScript"/>).</summary>
    public static void Classify(AppVersionsPlan plan, string output, Func<string, (string? Name, bool Deleted)> account)
    {
        var listed = new Dictionary<string, Listed>(StringComparer.OrdinalIgnoreCase);
        var provisioned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // name|version|publisher
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var f = line.Split('\t');
            if (f.Length >= 2 && f[0] == "V") { if (Identity(f[1].Trim()) is { } id) provisioned.Add(id); continue; }
            if (f.Length >= 2 && f[0] == "N") { plan.Notes.Add(f[1].Trim()); continue; }
            if (f.Length < 4 || f[0] != "P") continue;
            var l = new Listed
            {
                IsFramework = f[2].Trim().Equals("True", StringComparison.OrdinalIgnoreCase),
                NonRemovable = f[3].Trim().Equals("True", StringComparison.OrdinalIgnoreCase),
            };
            if (f.Length > 4)
                foreach (var u in f[4].Split('|', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = u.LastIndexOf('=');
                    var who = eq > 0 ? u[..eq] : u;
                    var state = eq > 0 ? u[(eq + 1)..].Trim() : "";
                    if (SidRx.Match(who) is { Success: true } m) l.Users.Add((m.Value, state));
                }
            if (f.Length > 5) l.Dependencies.AddRange(f[5].Split('|', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()));
            listed[f[1].Trim()] = l;
        }
        plan.Listed = listed.Count;
        var resolved = new Dictionary<string, (string? Name, bool Deleted)>(StringComparer.OrdinalIgnoreCase);
        (string? Name, bool Deleted) Who(string sid) => resolved.TryGetValue(sid, out var w) ? w : resolved[sid] = account(sid);
        foreach (var (name, l) in listed)
            foreach (var (sid, state) in l.Users)
            {
                if (sid == "S-1-5-18" || state.Equals("Staged", StringComparison.OrdinalIgnoreCase)
                    || state.Equals("NotInstalled", StringComparison.OrdinalIgnoreCase) || !Who(sid).Deleted) continue;
                if (!plan.Ghosts.TryGetValue(sid, out var pk)) plan.Ghosts[sid] = pk = new();
                if (!pk.Contains(name, StringComparer.OrdinalIgnoreCase)) pk.Add(name);
            }

        var dependents = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, l) in listed)
            foreach (var d in l.Dependencies)
            {
                if (d.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                if (!dependents.TryGetValue(d, out var who)) dependents[d] = who = new();
                who.Add(name);
            }

        foreach (var item in plan.Items)
        {
            if (!listed.TryGetValue(item.FullName, out var l))
            {
                if (Identity(item.FullName) is { } pid && provisioned.Contains(pid))
                {
                    item.State = AppVersionState.Used;
                    item.Reason = "provisioned: Windows installs it for every new account";
                }
                else
                {
                    item.State = AppVersionState.NotKnown;
                    item.Reason = "Windows lists no package by this name for any account — the folder is left over";
                }
                continue;
            }
            var reasons = new List<string>();
            if (l.NonRemovable) reasons.Add("Windows marks it non-removable");
            if (Identity(item.FullName) is { } id2 && provisioned.Contains(id2)) reasons.Add("provisioned: Windows installs it for every new account");
            if (dependents.TryGetValue(item.FullName, out var deps) && deps.Count > 0)
                reasons.Add((deps.Count == 1 ? "1 app depends on it: " : $"{deps.Count} apps depend on it: ")
                            + string.Join(", ", deps.Take(3).Select(Short)) + (deps.Count > 3 ? ", …" : ""));
            var users = new List<string>();
            var deleted = 0;
            foreach (var (sid, state) in l.Users)
            {
                if (sid == "S-1-5-18" || state.Equals("Staged", StringComparison.OrdinalIgnoreCase)
                    || state.Equals("NotInstalled", StringComparison.OrdinalIgnoreCase)) continue;
                var (name, gone) = Who(sid);
                if (gone) { deleted++; continue; }
                users.Add(name ?? sid);
            }
            if (users.Count > 0) reasons.Add("registered for " + string.Join(", ", users.Distinct()));
            if (reasons.Count > 0)
            {
                item.State = AppVersionState.Used;
                item.Reason = string.Join("; ", reasons);
            }
            else
            {
                item.State = AppVersionState.Unused;
                item.StagedOnly = deleted == 0;
                item.Reason = deleted == 0
                    ? "staged for the system only (S-1-5-18): installed for no account, no app depends on it — removed as SYSTEM"
                    : $"no account uses this version and no app depends on it; registered only for {(deleted == 1 ? "a deleted account" : $"{deleted} deleted accounts")} — removed with -AllUsers";
            }
        }
    }

    /// <summary>"name|version|publisher" of a package full name: a provisioned bundle and its parts share it, whatever
    /// their architecture or resource part.</summary>
    private static string? Identity(string fullName)
    {
        var m = PackageFolder.Match(fullName);
        return m.Success ? $"{m.Groups["name"].Value}|{m.Groups["ver"].Value}|{m.Groups["pub"].Value}" : null;
    }

    private static string Short(string fullName)
    {
        var m = PackageFolder.Match(fullName);
        return m.Success ? $"{m.Groups["name"].Value} {m.Groups["ver"].Value}" : fullName;
    }

    /// <summary>The account's name, and whether Windows confirms it no longer exists.</summary>
    private static (string? Name, bool Deleted) Account(string sid)
    {
        var p = SidResolver.Resolve(sid);
        bool deleted = p.Use == SidUse.DeletedAccount || (!p.Resolved && p.LookupError == 1332);
        return (p.Resolved ? p.Display : null, deleted);
    }

    private static void Measure(string folder, FileProbe probe, ref long bytes, ref int objects)
    {
        var entries = new List<DirEntry>();
        if (probe.ListDirectory(folder, entries) != 0) return;
        var prefix = folder.TrimEnd('\\') + "\\";
        foreach (var e in entries.ToList())
        {
            objects++;
            bool isDir = (e.Attributes & (uint)FileAttributes.Directory) != 0;
            bool isLink = (e.Attributes & (uint)FileAttributes.ReparsePoint) != 0;
            if (isDir && !isLink) Measure(prefix + e.Name, probe, ref bytes, ref objects);
            else if (!isDir) bytes += e.Size;
        }
    }

    /// <summary>Removes the chosen unused versions through Windows — staged ones as SYSTEM through a one-off scheduled task,
    /// the others with Remove-AppxPackage -AllUsers — and deletes the chosen folders Windows no longer knows. Then asks
    /// Windows again and looks at the disk: only that check decides what counts as removed and what was freed.
    /// Stops between items (and between SYSTEM runs) when cancelled.</summary>
    public static AppVersionsOutcome Run(IReadOnlyList<AppVersionItem> remove, IReadOnlyList<AppVersionItem> delete,
        Action<string, int, int> progress, CancellationToken ct)
    {
        var failed = new List<(string, string)>();
        var answers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // full name → Windows' raw answer
        var attempted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<AppVersionResult>();
        int deleted = 0, step = 0;
        var staged = remove.Where(i => i.StagedOnly).ToList();
        var allUsers = remove.Where(i => !i.StagedOnly).ToList();
        var chunks = staged.Chunk(SystemChunk).ToList();
        int total = allUsers.Count + chunks.Count + delete.Count + 1;
        bool cancelled = false;
        long freed = 0;

        foreach (var i in allUsers)
        {
            if (ct.IsCancellationRequested) { cancelled = true; break; }
            progress("Windows removes " + i.FullName, ++step, total);
            attempted.Add(i.FullName);
            var (_, output, error) = RunPowerShell(RemoveScript(i.FullName));
            var answer = output.Trim();
            answers[i.FullName] = answer.EndsWith("OK", StringComparison.Ordinal) ? "OK"
                : answer.StartsWith("ERR ", StringComparison.Ordinal) ? answer[4..] : (error.Length > 0 ? error : answer);
        }
        foreach (var chunk in chunks)
        {
            if (cancelled || ct.IsCancellationRequested) { cancelled = true; break; }
            progress($"Windows removes {chunk.Length} staged version{(chunk.Length == 1 ? "" : "s")} as SYSTEM (one-off scheduled task)…", ++step, total);
            foreach (var c in chunk) attempted.Add(c.FullName);
            var (_, output, error) = RunPowerShell(SystemRemoveScript(chunk.Select(c => c.FullName).ToList()));
            foreach (var raw in output.Split('\n'))
            {
                var f = raw.TrimEnd('\r').Split('\t');
                if (f.Length >= 2 && f[0] == "OK") answers[f[1].Trim()] = "OK";
                else if (f.Length >= 2 && f[0] == "ERR") answers[f[1].Trim()] = f.Length > 2 ? f[2].Trim() : "error";
                else if (f.Length >= 2 && f[0] == "N") failed.Add(("SYSTEM run", f[1].Trim()));
            }
            if (chunk.All(c => !answers.ContainsKey(c.FullName)) && error.Length > 0) failed.Add(("SYSTEM run", error));
        }
        if (delete.Count > 0 && !cancelled)
        {
            Privileges.EnableReadPrivileges();
            Privileges.Enable(Privileges.Restore);
            Privileges.Enable(Privileges.TakeOwnership);
        }
        foreach (var i in delete)
        {
            if (cancelled || ct.IsCancellationRequested) { cancelled = true; break; }
            progress("Deleting " + i.Folder, ++step, total);
            var problems = new List<(string Path, int Error)>();
            long bytes = 0;
            bool ok = OrphanCleanup.DeleteTree(i.Folder, problems, ref bytes, ct);
            if (ok) deleted++;
            freed += bytes;
            var full = problems.Count == 0 ? null
                : string.Join("\n", problems.Take(20).Select(x => $"{x.Path}: error {x.Error}")) + (problems.Count > 20 ? $"\n… and {problems.Count - 20:N0} more" : "");
            results.Add(new AppVersionResult(i, AppRoute.DeleteFolder, ok ? "deleted" : $"{problems.Count:N0} could not be deleted (in use or new)",
                full, ok ? "gone" : "partly deleted — what could not be deleted stays", ok));
        }

        // The check: ask Windows again and look at the disk. Windows' "OK" is never taken as proof.
        progress("Asking Windows again and checking the disk…", ++step, total);
        int gone = 0, onDisk = 0, notRemoved = 0;
        var (queryCode, again, againError) = RunPowerShell(QueryScript);
        var stillListed = ListedNames(again);
        bool checkedOk = queryCode == 0 || again.Contains("P\t", StringComparison.Ordinal);
        if (!checkedOk) failed.Add(("check", "Windows could not be asked again: " + (againError.Length > 0 ? againError : $"exit code {queryCode}")));
        foreach (var i in remove)
        {
            if (!attempted.Contains(i.FullName)) continue;   // cancelled before its turn
            var route = i.StagedOnly ? AppRoute.AsSystem : AppRoute.AllUsers;
            var raw = answers.TryGetValue(i.FullName, out var a) ? a : (i.StagedOnly ? "no answer from the SYSTEM run" : "no answer");
            var answer = Plain(raw);
            var full = raw == "OK" ? null : raw;
            string status;
            bool isGone = false;
            if (!checkedOk) status = "not checked — Windows could not be asked again";
            else if (stillListed.Contains(i.FullName))
            {
                notRemoved++;
                status = answer == "OK" ? "Windows answered OK but still lists it — not removed" : "Windows still lists it — not removed";
            }
            else if (Directory.Exists(i.Folder)) { onDisk++; status = "Windows no longer lists it, but its folder is still on disk"; }
            else { gone++; freed += i.Bytes; isGone = true; status = "removed and gone"; }
            results.Add(new AppVersionResult(i, route, answer, full, status, isGone));
        }
        return new(gone, onDisk, notRemoved, deleted, freed, failed, cancelled, checkedOk, results);
    }

    /// <summary>Windows' deployment answer in one plain line, with the error code when there is one. The full text stays
    /// available separately.</summary>
    public static string Plain(string windowsText)
    {
        var t = windowsText.Trim();
        if (t.Length == 0 || t == "OK") return "OK";
        var m = Regex.Match(t, @"0x[0-9A-Fa-f]{8}");
        var code = m.Success ? m.Value.ToUpperInvariant().Replace("0X", "0x") : null;
        string? plain = code switch
        {
            "0x80073D02" => "in use by a running app — close it or restart Windows, then run this again",
            "0x80073CF1" => "Windows found no package by this name",
            "0x80073CFA" => "Windows refused the removal",
            "0x80073D19" => "an app that depends on it is still installed",
            "0x80070005" => "access denied",
            _ => null,
        };
        if (plain == null && t.Contains("Value does not fall within the expected range", StringComparison.OrdinalIgnoreCase))
            plain = "Windows rejected the request (for example an account it cannot resolve)";
        if (plain == null)
        {
            var first = t.Split(new[] { ". ", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries)[0];
            plain = first.Length > 140 ? first[..140] + "…" : first;
        }
        return code != null ? $"{plain} ({code})" : plain;
    }

    /// <summary>The package full names in an answer of <see cref="QueryScript"/>.</summary>
    public static HashSet<string> ListedNames(string output)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in output.Split('\n'))
        {
            var f = raw.TrimEnd('\r').Split('\t');
            if (f.Length >= 2 && f[0] == "P") set.Add(f[1].Trim());
        }
        return set;
    }

    /// <summary>Staged versions per SYSTEM run: keeps the scheduled task's command line short (a few thousand characters).</summary>
    public const int SystemChunk = 5;

    /// <summary>The name prefix of the one-off scheduled task; any task with it is a leftover of an interrupted run.</summary>
    public const string TaskPrefix = "AclLegibility-";

    /// <summary>
    /// Removal as SYSTEM, run from the app's own elevated PowerShell: removes leftover AclLegibility-* tasks, registers a
    /// one-off task AclLegibility-&lt;id&gt; that runs as SYSTEM, starts it, waits for it, then stops and unregisters it
    /// (also when anything fails). As SYSTEM, Remove-AppxPackage removes what is staged for the system. The task writes
    /// one line per package to a file with a random name in %SystemRoot%\Temp, which is read back and deleted.
    /// </summary>
    public static string SystemRemoveScript(IReadOnlyList<string> fullNames)
    {
        var id = Guid.NewGuid().ToString("N");
        var output = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", $"{TaskPrefix}{id}.txt");
        string Q(string v) => "'" + v.Replace("'", "''") + "'";
        var inner = $$"""
            $ErrorActionPreference = 'Stop'
            $out = {{Q(output)}}
            foreach ($n in @({{string.Join(", ", fullNames.Select(Q))}})) {
              try { Remove-AppxPackage -Package $n; Add-Content -LiteralPath $out -Value ("OK`t" + $n) -Encoding UTF8 }
              catch { Add-Content -LiteralPath $out -Value ("ERR`t" + $n + "`t" + ($_.Exception.Message -replace '\s+', ' ')) -Encoding UTF8 }
            }
            Add-Content -LiteralPath $out -Value 'DONE' -Encoding UTF8
            """;
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(inner));
        return $$"""
            $ErrorActionPreference = 'Stop'
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            $name = {{Q(TaskPrefix + id)}}
            $out = {{Q(output)}}
            Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like '{{TaskPrefix}}*' } | ForEach-Object {
              Stop-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
              Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue }
            $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $a = New-ScheduledTaskAction -Execute $ps -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {{encoded}}'
            try {
              Register-ScheduledTask -TaskName $name -Action $a -User 'SYSTEM' -RunLevel Highest | Out-Null
              Start-ScheduledTask -TaskName $name
              $start = Get-Date
              while ($true) {
                Start-Sleep -Milliseconds 1000
                if ((Test-Path -LiteralPath $out) -and ((Get-Content -LiteralPath $out -Encoding UTF8) -contains 'DONE')) { break }
                $state = (Get-ScheduledTask -TaskName $name).State
                if ("$state" -ne 'Running' -and ((Get-Date) - $start).TotalSeconds -gt 15) { break }
                if (((Get-Date) - $start).TotalMinutes -gt 30) { [Console]::Out.WriteLine("N`tThe SYSTEM run did not finish within 30 minutes and was stopped."); break }
              }
            }
            finally {
              Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
              Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $out) {
              Get-Content -LiteralPath $out -Encoding UTF8 | ForEach-Object { if ($_ -ne 'DONE') { [Console]::Out.WriteLine($_) } }
              Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            }
            else { [Console]::Out.WriteLine("N`tThe SYSTEM run left no result.") }
            """;
    }

    /// <summary>Runs one script in Windows PowerShell 5.1 (the one that has the Appx module), without profile, and returns
    /// its exit code, output and error text.</summary>
    public static (int Code, string Output, string Error) RunPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo(PowerShellPath, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("powershell.exe could not be started.");
        var err = p.StandardError.ReadToEndAsync();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, output, CleanError(err.Result));
    }

    /// <summary>PowerShell writes errors from an encoded command as CLIXML; keep only the readable text.</summary>
    private static string CleanError(string text)
    {
        if (!text.Contains("#< CLIXML", StringComparison.Ordinal)) return text.Trim();
        var parts = Regex.Matches(text, @"<S S=""Error"">(.*?)</S>").Select(m => m.Groups[1].Value.Replace("_x000D__x000A_", " "));
        return System.Net.WebUtility.HtmlDecode(string.Join("", parts)).Trim();
    }
}
