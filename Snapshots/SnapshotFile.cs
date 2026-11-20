using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using AclLegibility.Model;

namespace AclLegibility.Snapshots;

/// <summary>
/// Compact, versioned scan snapshot (.aclsnap): gzip-compressed binary. Holds everything needed to
/// re-classify on another machine later — raw descriptors, names, OS facts and folder layout —
/// so a scan of a clean VM can become a reference baseline without changing the format.
/// </summary>
public static class SnapshotFile
{
    private const string Magic = "ACLLEGIBILITY-SNAPSHOT";
    // v4 (0.1.7): link counts are correct. v1–v3 recorded part of the file ID instead; they are discarded on load.
    // v5 (0.1.9): Windows' profile list (SID → folder).
    private const int FormatVersion = 8;

    public static void Save(ScanResult r, string path)
    {
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Optimal);
        using var w = new BinaryWriter(gz, Encoding.UTF8);
        w.Write(Magic);
        w.Write(FormatVersion);
        w.Write(r.ScannedUtc.ToBinary());
        w.Write(r.Duration.Ticks);
        w.Write(r.ObjectCount);
        w.Write(r.ErrorCount);
        w.Write(r.Cancelled);
        WriteList(w, r.PrivilegesEnabled, w.Write);

        var os = r.Os;
        w.Write(os.ProductName); w.Write(os.EditionId); w.Write(os.DisplayVersion);
        w.Write(os.Major); w.Write(os.Minor); w.Write(os.Build); w.Write(os.Ubr);
        w.Write(os.InstallationType); w.Write(os.IsServer); w.Write(os.Architecture); w.Write(os.UiLanguage);
        w.Write(os.ComputerName); WriteN(w, os.MachineSid); w.Write(os.DomainJoined); WriteN(w, os.DomainName); WriteN(w, os.DnsDomainName);
        w.Write(os.Paths.Count);
        foreach (var kv in os.Paths) { w.Write(kv.Key); w.Write(kv.Value); }
        w.Write(os.Profiles.Count);
        foreach (var kv in os.Profiles) { w.Write(kv.Key); w.Write(kv.Value); }
        w.Write(os.CurrentInstallUtc?.ToBinary() ?? 0L);
        w.Write(os.UpgradedFrom.Count);
        foreach (var u in os.UpgradedFrom)
        {
            w.Write(u.Product); w.Write(u.Build); w.Write(u.Ubr);
            w.Write(u.InstalledUtc?.ToBinary() ?? 0L); w.Write(u.ReplacedLocal?.ToBinary() ?? 0L);
            w.Write(u.DisplayVersion);
        }

        var sds = r.Descriptors.Snapshot();
        w.Write(sds.Count);
        foreach (var sd in sds) { w.Write(sd.Length); w.Write(sd); }

        w.Write(r.Names.Count);
        foreach (var p in r.Names.Values) { w.Write(p.Sid); WriteN(w, p.Domain); WriteN(w, p.Name); w.Write((int)p.Use); w.Write(p.LookupError); }

        var inv = r.Inventory;
        WriteList(w, inv.Users, u => { w.Write(u.Name); WriteN(w, u.Sid); WriteN(w, u.Comment); w.Write(u.Flags); });
        WriteList(w, inv.Groups, g =>
        {
            w.Write(g.Name); WriteN(w, g.Sid); WriteN(w, g.Comment);
            WriteList(w, g.Members, m => { w.Write(m.Sid); w.Write(m.Name); w.Write((int)m.Use); });
        });
        WriteList(w, inv.Shares, s =>
        {
            w.Write(s.Name); WriteN(w, s.Path); w.Write(s.Type); WriteN(w, s.Remark);
            w.Write(s.SecurityDescriptor?.Length ?? -1);
            if (s.SecurityDescriptor != null) w.Write(s.SecurityDescriptor);
        });
        WriteList(w, inv.Notes, w.Write);

        // nodes: pre-order, each record followed by its child count
        w.Write(r.Roots.Count);
        var stack = new Stack<ScanNode>();
        for (int i = r.Roots.Count - 1; i >= 0; i--) stack.Push(r.Roots[i]);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            WriteNode(w, n);
            var c = n.Children;
            w.Write(c?.Count ?? 0);
            if (c != null) for (int i = c.Count - 1; i >= 0; i--) stack.Push(c[i]);
        }
        w.Write("END");
    }

    private static void WriteNode(BinaryWriter w, ScanNode n)
    {
        w.Write(n.Name);
        w.Write(n.Attributes);
        w.Write(n.SdIndex);
        w.Write((uint)n.Flags);
        w.Write(n.LinkCount);
        w.Write(n.Size);
        w.Write(n.Created);
        WriteN(w, n.ShortName);
        var x = n.Extra;
        byte mask = 0;
        if (x?.Streams != null) mask |= 1;
        if (x?.Reparse != null) mask |= 2;
        if (x != null && (x.ErrorCode != 0 || x.ErrorStage != null)) mask |= 4;
        if (x?.ObjectId != null) mask |= 8;
        w.Write(mask);
        if ((mask & 1) != 0) WriteList(w, x!.Streams!, s => { w.Write(s.Name); w.Write(s.Size); });
        if ((mask & 2) != 0) { var rp = x!.Reparse!; w.Write(rp.Tag); WriteN(w, rp.SubstituteName); WriteN(w, rp.PrintName); WriteN(w, rp.Extra); }
        if ((mask & 4) != 0) { w.Write(x!.ErrorCode); WriteN(w, x.ErrorStage); }
        if ((mask & 8) != 0) w.Write(x!.ObjectId!.Value.ToByteArray());
    }

    public static ScanResult Load(string path)
    {
        using var fs = File.OpenRead(path);
        using var gz = new GZipStream(fs, CompressionMode.Decompress);
        using var rd = new BinaryReader(gz, Encoding.UTF8);
        if (rd.ReadString() != Magic) throw new InvalidDataException("Not an AclLegibility snapshot.");
        int ver = rd.ReadInt32();
        if (ver > FormatVersion) throw new InvalidDataException($"Snapshot format {ver} is newer than this version of the app supports ({FormatVersion}).");

        var r = new ScanResult { IsLive = false, SourceFile = path };
        r.ScannedUtc = DateTime.FromBinary(rd.ReadInt64());
        r.Duration = TimeSpan.FromTicks(rd.ReadInt64());
        r.ObjectCount = rd.ReadInt64();
        r.ErrorCount = rd.ReadInt64();
        if (ver >= 2) r.Cancelled = rd.ReadBoolean();
        r.PrivilegesEnabled = ReadList(rd, rd.ReadString);

        var os = r.Os;
        os.ProductName = rd.ReadString(); os.EditionId = rd.ReadString(); os.DisplayVersion = rd.ReadString();
        os.Major = rd.ReadInt32(); os.Minor = rd.ReadInt32(); os.Build = rd.ReadInt32(); os.Ubr = rd.ReadInt32();
        os.InstallationType = rd.ReadString(); os.IsServer = rd.ReadBoolean(); os.Architecture = rd.ReadString(); os.UiLanguage = rd.ReadString();
        os.ComputerName = rd.ReadString(); os.MachineSid = ReadN(rd); os.DomainJoined = rd.ReadBoolean(); os.DomainName = ReadN(rd); os.DnsDomainName = ReadN(rd);
        int pc = rd.ReadInt32();
        for (int i = 0; i < pc; i++) os.Paths[rd.ReadString()] = rd.ReadString();
        if (ver >= 5) { int prc = rd.ReadInt32(); for (int i = 0; i < prc; i++) os.Profiles[rd.ReadString()] = rd.ReadString(); }
        if (ver >= 6)
        {
            static DateTime? D(long v) => v == 0 ? null : DateTime.FromBinary(v);
            os.CurrentInstallUtc = D(rd.ReadInt64());
            int uc = rd.ReadInt32();
            for (int i = 0; i < uc; i++)
            {
                var u = new SourceOs { Product = rd.ReadString(), Build = rd.ReadInt32(), Ubr = rd.ReadInt32(), InstalledUtc = D(rd.ReadInt64()), ReplacedLocal = D(rd.ReadInt64()) };
                if (ver >= 7) u.DisplayVersion = rd.ReadString();
                os.UpgradedFrom.Add(u);
            }
        }

        int sdc = rd.ReadInt32();
        for (int i = 0; i < sdc; i++) r.Descriptors.AddOwned(rd.ReadBytes(rd.ReadInt32()));

        int nc = rd.ReadInt32();
        for (int i = 0; i < nc; i++)
        {
            var p = new PrincipalName { Sid = rd.ReadString(), Domain = ReadN(rd), Name = ReadN(rd), Use = (SidUse)rd.ReadInt32() };
            if (ver >= 3) p.LookupError = rd.ReadInt32();
            r.Names[p.Sid] = p;
        }

        var inv = r.Inventory;
        inv.Users = ReadList(rd, () => new LocalUser { Name = rd.ReadString(), Sid = ReadN(rd), Comment = ReadN(rd), Flags = rd.ReadUInt32() });
        inv.Groups = ReadList(rd, () => new LocalGroup
        {
            Name = rd.ReadString(), Sid = ReadN(rd), Comment = ReadN(rd),
            Members = ReadList(rd, () => new GroupMember { Sid = rd.ReadString(), Name = rd.ReadString(), Use = (SidUse)rd.ReadInt32() }),
        });
        inv.Shares = ReadList(rd, () =>
        {
            var s = new ShareEntry { Name = rd.ReadString(), Path = ReadN(rd), Type = rd.ReadUInt32(), Remark = ReadN(rd) };
            int len = rd.ReadInt32();
            if (len >= 0) s.SecurityDescriptor = rd.ReadBytes(len);
            return s;
        });
        inv.Notes = ReadList(rd, rd.ReadString);

        int roots = rd.ReadInt32();
        // stack of (parent, remaining children)
        var stack = new Stack<(ScanNode Node, int Remaining)>();
        for (int i = 0; i < roots; i++)
        {
            var root = ReadNode(rd, null, ver);
            r.Roots.Add(root);
            int cc = rd.ReadInt32();
            if (cc > 0) { root.Children = new List<ScanNode>(cc); stack.Push((root, cc)); }
            while (stack.Count > 0)
            {
                var (parent, remaining) = stack.Pop();
                if (remaining == 0) continue;
                stack.Push((parent, remaining - 1));
                var child = ReadNode(rd, parent, ver);
                parent.Children!.Add(child);
                int c = rd.ReadInt32();
                if (c > 0) { child.Children = new List<ScanNode>(c); stack.Push((child, c)); }
            }
        }
        if (rd.ReadString() != "END") throw new InvalidDataException("Snapshot is truncated.");
        if (ver < 4)
        {
            foreach (var n in r.AllNodes()) n.LinkCount = 0;
            r.LoadNote = "Hard-link counts are not shown: versions up to 0.1.6 recorded them wrongly.";
        }
        if (ver < 8)
        {
            // Up to 0.2.3 a folder without streams could be given the streams of the file scanned before it.
            int dropped = 0;
            foreach (var n in r.AllNodes())
                if (n.IsDirectory && n.Extra?.Streams is { Count: > 0 }) { n.Extra.Streams = null; dropped++; }
            if (dropped > 0)
            {
                var note = $"Streams on {dropped:N0} folder{(dropped == 1 ? "" : "s")} are not shown: versions up to 0.2.3 could copy a file's streams onto the folder scanned after it.";
                r.LoadNote = r.LoadNote == null ? note : r.LoadNote + " " + note;
            }
        }
        return r;
    }

    private static ScanNode ReadNode(BinaryReader rd, ScanNode? parent, int ver)
    {
        var n = new ScanNode
        {
            Parent = parent,
            Name = rd.ReadString(),
            Attributes = rd.ReadUInt32(),
            SdIndex = rd.ReadInt32(),
            Flags = (NodeFlags)rd.ReadUInt32(),
            LinkCount = rd.ReadUInt32(),
            Size = rd.ReadInt64(),
            Created = ver >= 7 ? rd.ReadInt64() : 0,
            ShortName = ReadN(rd),
        };
        byte mask = rd.ReadByte();
        if (mask != 0)
        {
            var x = n.EnsureExtra();
            if ((mask & 1) != 0) x.Streams = ReadList(rd, () => new StreamEntry { Name = rd.ReadString(), Size = rd.ReadInt64() });
            if ((mask & 2) != 0) x.Reparse = new ReparseInfo { Tag = rd.ReadUInt32(), SubstituteName = ReadN(rd), PrintName = ReadN(rd), Extra = ReadN(rd) };
            if ((mask & 4) != 0) { x.ErrorCode = rd.ReadInt32(); x.ErrorStage = ReadN(rd); }
            if ((mask & 8) != 0) x.ObjectId = new Guid(rd.ReadBytes(16));
        }
        return n;
    }

    private static void WriteN(BinaryWriter w, string? s) { w.Write(s != null); if (s != null) w.Write(s); }
    private static string? ReadN(BinaryReader r) => r.ReadBoolean() ? r.ReadString() : null;

    private static void WriteList<T>(BinaryWriter w, List<T> list, Action<T> write)
    {
        w.Write(list.Count);
        foreach (var x in list) write(x);
    }

    private static List<T> ReadList<T>(BinaryReader r, Func<T> read)
    {
        int n = r.ReadInt32();
        var list = new List<T>(n);
        for (int i = 0; i < n; i++) list.Add(read());
        return list;
    }
}
