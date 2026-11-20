using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Diagnostics;
using AclLegibility.Model;
using AclLegibility.Native;

namespace AclLegibility.Scanning;

public sealed class ScanProgress
{
    public long Objects;
    public long Directories;
    public long Errors;
    public long Pending;
    public volatile string Current = "";
    public volatile string Phase = "";
}

/// <summary>Walks one or more roots in parallel. Reparse points that are name surrogates
/// (junctions, symlinks) are recorded but never followed.</summary>
public sealed class Scanner
{
    private readonly ScanResult _result;
    private readonly ScanProgress _progress;
    private readonly CancellationToken _ct;
    private readonly bool _canReadSacl;

    private Scanner(ScanResult result, ScanProgress progress, bool canReadSacl, CancellationToken ct)
    {
        _result = result; _progress = progress; _canReadSacl = canReadSacl; _ct = ct;
    }

    public static IReadOnlyList<string> FixedVolumeRoots() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

    public static ScanResult Run(IReadOnlyList<string> roots, ScanProgress progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var result = new ScanResult { IsLive = true, ScannedUtc = DateTime.UtcNow };

        progress.Phase = "Enabling privileges";
        result.PrivilegesEnabled = Privileges.EnableReadPrivileges().ToList();
        bool canSacl = result.PrivilegesEnabled.Contains(Privileges.Security);

        progress.Phase = "Reading system information";
        result.Os = SystemInventory.DetectOs();
        result.Inventory = SystemInventory.Collect();

        var scanner = new Scanner(result, progress, canSacl, ct);
        progress.Phase = "Scanning";
        scanner.Walk(roots);

        progress.Phase = "Resolving account names";
        ResolveNames(result);

        result.ObjectCount = progress.Objects;
        result.ErrorCount = progress.Errors;
        result.Cancelled = ct.IsCancellationRequested;
        result.Duration = sw.Elapsed;
        return result;
    }

    private void Walk(IReadOnlyList<string> roots)
    {
        var queue = new BlockingCollection<ScanNode>(new ConcurrentQueue<ScanNode>());
        var probeForRoots = new FileProbe(_canReadSacl);
        foreach (var r in roots)
        {
            var full = Path.GetFullPath(r);
            var isVolumeRoot = Path.GetPathRoot(full)?.Equals(full, StringComparison.OrdinalIgnoreCase) == true;
            var root = new ScanNode
            {
                Name = isVolumeRoot ? full : full.TrimEnd('\\'),
                Flags = NodeFlags.Directory | (isVolumeRoot ? NodeFlags.IsVolumeRoot : 0),
            };
            try { root.Attributes = (uint)File.GetAttributes(full); } catch { root.Attributes = (uint)FileAttributes.Directory; }
            try { root.Created = Directory.GetCreationTimeUtc(full).ToFileTimeUtc(); } catch { }
            probeForRoots.Probe(root.Name, root, _result.Descriptors);
            _result.Roots.Add(root);
            Interlocked.Increment(ref _progress.Objects);
            Interlocked.Increment(ref _progress.Pending);
            queue.Add(root);
        }
        if (_result.Roots.Count == 0) return;

        int workers = Math.Clamp(Environment.ProcessorCount, 2, 8);
        var tasks = new Task[workers];
        for (int i = 0; i < workers; i++)
        {
            tasks[i] = Task.Factory.StartNew(() =>
            {
                var probe = new FileProbe(_canReadSacl);
                var entries = new List<DirEntry>(256);
                foreach (var dir in queue.GetConsumingEnumerable())
                {
                    try
                    {
                        if (!_ct.IsCancellationRequested) ProcessDirectory(dir, probe, entries, queue);
                    }
                    catch (Exception ex)
                    {
                        dir.Flags |= NodeFlags.ListFailed;
                        var x = dir.EnsureExtra(); x.ErrorStage = "list: " + ex.Message;
                        Interlocked.Increment(ref _progress.Errors);
                    }
                    finally
                    {
                        if (Interlocked.Decrement(ref _progress.Pending) == 0) queue.CompleteAdding();
                    }
                }
            }, TaskCreationOptions.LongRunning);
        }
        Task.WaitAll(tasks);
    }

    private void ProcessDirectory(ScanNode dir, FileProbe probe, List<DirEntry> entries, BlockingCollection<ScanNode> queue)
    {
        var path = dir.FullPath;
        _progress.Current = path;
        int err = probe.ListDirectory(path, entries);
        Interlocked.Increment(ref _progress.Directories);
        if (err != 0)
        {
            dir.Flags |= NodeFlags.ListFailed;
            var x = dir.EnsureExtra();
            if (x.ErrorCode == 0) { x.ErrorCode = err; x.ErrorStage = "list"; }
            Interlocked.Increment(ref _progress.Errors);
            return;
        }
        if (entries.Count == 0) return;

        var children = new List<ScanNode>(entries.Count);
        var prefix = path.EndsWith('\\') ? path : path + "\\";
        foreach (var e in entries)
        {
            if (_ct.IsCancellationRequested) break;
            bool isDir = (e.Attributes & (uint)FileAttributes.Directory) != 0;
            var child = new ScanNode
            {
                Parent = dir,
                Name = e.Name,
                Attributes = e.Attributes,
                Size = isDir ? 0 : e.Size,
                Created = e.Created,
                ShortName = e.ShortName,
                Flags = isDir ? NodeFlags.Directory : NodeFlags.None,
            };
            if (!probe.Probe(prefix + e.Name, child, _result.Descriptors))
                Interlocked.Increment(ref _progress.Errors);
            Interlocked.Increment(ref _progress.Objects);
            children.Add(child);

            if (isDir)
            {
                var rp = child.Extra?.Reparse;
                bool isReparse = (e.Attributes & (uint)FileAttributes.ReparsePoint) != 0;
                // Do not follow junctions/symlinks/mount points; do descend into e.g. cloud placeholder folders.
                if (isReparse && (rp == null || rp.Tag == 0 || rp.IsNameSurrogate))
                {
                    child.Flags |= NodeFlags.NotFollowed;
                    continue;
                }
                Interlocked.Increment(ref _progress.Pending);
                queue.Add(child);
            }
        }
        children.Sort((a, b) =>
        {
            int d = (b.IsDirectory ? 1 : 0) - (a.IsDirectory ? 1 : 0);
            return d != 0 ? d : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });
        dir.Children = children;
    }

    /// <summary>Lists a folder again from scratch, single-threaded: the old children are dropped and everything below is
    /// read fresh — used after the component-store clean-up, which deletes whole folders.</summary>
    public static void Relist(ScanResult result, ScanNode top, Action<long>? progress = null)
    {
        var p = new ScanProgress();
        var s = new Scanner(result, p, result.PrivilegesEnabled.Contains(Privileges.Security), CancellationToken.None);
        var probe = new FileProbe(s._canReadSacl);
        var entries = new List<DirEntry>(256);
        var queue = new BlockingCollection<ScanNode>();
        top.Children = null;
        top.Flags &= ~NodeFlags.ListFailed;
        queue.Add(top);
        while (queue.TryTake(out var dir))
        {
            try { s.ProcessDirectory(dir, probe, entries, queue); }
            catch (Exception ex) { dir.Flags |= NodeFlags.ListFailed; dir.EnsureExtra().ErrorStage = "list: " + ex.Message; }
            progress?.Invoke(p.Objects);
        }
        ResolveNames(result);
    }

    /// <summary>Re-reads every object below (and including) a node in place — used after Reset to inherit,
    /// so the view shows the new state without a full rescan.</summary>
    public static void Reprobe(ScanResult result, ScanNode top, Action<int>? progress = null, bool subtree = true, bool resolveNames = true)
    {
        var probe = new FileProbe(result.PrivilegesEnabled.Contains(Privileges.Security));
        var stack = new Stack<ScanNode>();
        stack.Push(top);
        int done = 0;
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            n.SdIndex = -1;
            var listError = (n.Flags & NodeFlags.ListFailed) != 0 ? (n.Extra?.ErrorCode, n.Extra?.ErrorStage) : default;
            n.Flags &= NodeFlags.Directory | NodeFlags.IsVolumeRoot | NodeFlags.NotFollowed | NodeFlags.ListFailed;
            n.Extra = null;
            probe.Probe(n.FullPath, n, result.Descriptors);
            if ((n.Flags & NodeFlags.ListFailed) != 0 && n.Extra?.ErrorCode is null or 0)
            {
                var x = n.EnsureExtra(); x.ErrorCode = listError.Item1 ?? 0; x.ErrorStage = listError.Item2;
            }
            if (++done % 500 == 0) progress?.Invoke(done);
            if (subtree && n.Children != null) foreach (var c in n.Children) stack.Push(c);
        }
        if (resolveNames) ResolveNames(result);
    }

    /// <summary>Resolves every SID found in descriptors, shares and group memberships.</summary>
    public static void ResolveNames(ScanResult result)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in result.Descriptors.Snapshot())
            foreach (var s in new Security.SdInfo(raw).AllSids()) sids.Add(s);
        foreach (var sh in result.Inventory.Shares)
            if (sh.SecurityDescriptor != null) foreach (var s in new Security.SdInfo(sh.SecurityDescriptor).AllSids()) sids.Add(s);
        foreach (var g in result.Inventory.Groups)
        {
            if (g.Sid != null) sids.Add(g.Sid);
            foreach (var m in g.Members) if (!string.IsNullOrEmpty(m.Sid)) sids.Add(m.Sid);
        }
        foreach (var u in result.Inventory.Users) if (u.Sid != null) sids.Add(u.Sid);
        foreach (var s in result.Inventory.AccountTraces.Keys) sids.Add(s);
        foreach (var s in sids)
        {
            if (string.IsNullOrEmpty(s)) continue;
            result.Names[s] = SidResolver.Resolve(s);
        }
        // Capability SIDs cannot be looked up; derive known names forwards and match (kept in snapshots).
        CapabilityNames.Fill(result);
    }
}
