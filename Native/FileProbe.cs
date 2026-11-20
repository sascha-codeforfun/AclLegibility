using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using AclLegibility.Model;
using Microsoft.Win32.SafeHandles;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Native;

public struct DirEntry
{
    public string Name;
    public string? ShortName;
    public uint Attributes;
    public long Size;
    /// <summary>Creation time as a FILETIME (UTC), from the directory listing itself, so it costs nothing extra.</summary>
    public long Created;
}

/// <summary>Reads everything about one object through a single handle opened with backup semantics.
/// One instance per worker thread (it owns reusable buffers).</summary>
public sealed unsafe class FileProbe
{
    private byte[] _sdBuf = new byte[4096];
    private byte[] _streamBuf = new byte[16 * 1024];
    private readonly byte[] _reparseBuf = new byte[16 * 1024 + 64];
    private readonly byte[] _dirBuf = new byte[128 * 1024];
    private readonly byte[] _small = new byte[128];
    private readonly bool _canReadSacl;

    public FileProbe(bool canReadSacl) { _canReadSacl = canReadSacl; }

    public static string Long(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path[2..];
        return @"\\?\" + path;
    }

    private SafeFileHandle Open(string longPath, bool withSacl)
    {
        uint access = READ_CONTROL | FILE_READ_ATTRIBUTES | (withSacl ? ACCESS_SYSTEM_SECURITY : 0);
        return CreateFileW(longPath, access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, IntPtr.Zero);
    }

    /// <summary>Probes one object and fills the node. Returns false on a hard failure (error recorded on the node).</summary>
    public bool Probe(string path, ScanNode node, SdTable sds)
    {
        var lp = Long(path);
        bool withSacl = _canReadSacl;
        var h = Open(lp, withSacl);
        if (h.IsInvalid && withSacl)
        {
            h.Dispose();
            withSacl = false;
            h = Open(lp, false);
        }
        if (h.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            h.Dispose();
            node.Flags |= NodeFlags.Unreadable;
            var x = node.EnsureExtra(); x.ErrorCode = err; x.ErrorStage = "open";
            return false;
        }
        using (h)
        {
            // Security descriptor
            uint info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION
                        | (withSacl ? SACL_SECURITY_INFORMATION : 0);
            if (ReadSd(h, info, out int sdLen))
            {
                node.SdIndex = sds.Add(_sdBuf.AsSpan(0, sdLen));
                if (withSacl) node.Flags |= NodeFlags.SdIncludesSacl;
            }
            else
            {
                node.Flags |= NodeFlags.Unreadable;
                var x = node.EnsureExtra(); x.ErrorCode = Marshal.GetLastWin32Error(); x.ErrorStage = "security";
            }

            if (GetFileInformationByHandle(h, out var bhi))
            {
                node.LinkCount = bhi.NumberOfLinks;
                if (node.Attributes == 0) node.Attributes = bhi.FileAttributes;
            }

            if (node.IsDirectory) ReadCaseSensitive(h, node);
            ReadStreams(h, node);
            ReadObjectId(h, node);
            if ((node.Attributes & (uint)FileAttributes.ReparsePoint) != 0) ReadReparse(h, node);
        }
        return true;
    }

    private bool ReadSd(SafeFileHandle h, uint info, out int len)
    {
        len = 0;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            bool ok;
            int needed;
            var buf = _sdBuf;
            fixed (byte* p = buf)
                ok = GetKernelObjectSecurity(h, info, p, buf.Length, out needed);
            if (ok) { len = SdLength(buf.Length); return true; }
            if (Marshal.GetLastWin32Error() != 122 /*ERROR_INSUFFICIENT_BUFFER*/ || needed <= buf.Length) return false;
            _sdBuf = new byte[needed];
        }
        return false;
    }

    /// <summary>Exact length of the self-relative SD in the buffer (GetKernelObjectSecurity does not report it on success).</summary>
    private int SdLength(int max)
    {
        var b = _sdBuf.AsSpan(0, max);
        int end = 20;
        int oOwner = BinaryPrimitives.ReadInt32LittleEndian(b[4..]);
        int oGroup = BinaryPrimitives.ReadInt32LittleEndian(b[8..]);
        int oSacl = BinaryPrimitives.ReadInt32LittleEndian(b[12..]);
        int oDacl = BinaryPrimitives.ReadInt32LittleEndian(b[16..]);
        if (oOwner > 0 && oOwner + 8 <= max) end = Math.Max(end, oOwner + 8 + 4 * b[oOwner + 1]);
        if (oGroup > 0 && oGroup + 8 <= max) end = Math.Max(end, oGroup + 8 + 4 * b[oGroup + 1]);
        if (oSacl > 0 && oSacl + 4 <= max) end = Math.Max(end, oSacl + BinaryPrimitives.ReadUInt16LittleEndian(b[(oSacl + 2)..]));
        if (oDacl > 0 && oDacl + 4 <= max) end = Math.Max(end, oDacl + BinaryPrimitives.ReadUInt16LittleEndian(b[(oDacl + 2)..]));
        return Math.Min(end, max);
    }

    private void ReadCaseSensitive(SafeFileHandle h, ScanNode node)
    {
        fixed (byte* p = _small)
        {
            if (GetFileInformationByHandleEx(h, FileCaseSensitiveInfo, p, 4) && (BinaryPrimitives.ReadUInt32LittleEndian(_small) & 1) != 0)
                node.Flags |= NodeFlags.CaseSensitive;
        }
    }

    private void ReadStreams(SafeFileHandle h, ScanNode node)
    {
        for (int attempt = 0; attempt < 4; attempt++)
        {
            int status;
            IO_STATUS_BLOCK io;
            fixed (byte* p = _streamBuf)
                status = NtQueryInformationFile(h, out io, p, _streamBuf.Length, FileStreamInformation);
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH)
            {
                _streamBuf = new byte[_streamBuf.Length * 4];
                continue;
            }
            if (status != STATUS_SUCCESS) return;
            // Only what NTFS wrote this time counts. A folder without streams answers with 0 bytes; parsing the reused
            // buffer anyway handed folders the streams of the file read before them (up to 0.2.3).
            int written = (int)Math.Min((long)io.Information, _streamBuf.Length);
            if (written <= 0) return;
            ParseStreams(node, written);
            return;
        }
    }

    private void ParseStreams(ScanNode node, int length)
    {
        var b = _streamBuf.AsSpan(0, length);
        int pos = 0;
        List<StreamEntry>? list = null;
        while (pos + 24 <= b.Length)
        {
            int next = BinaryPrimitives.ReadInt32LittleEndian(b[pos..]);
            int nameLen = BinaryPrimitives.ReadInt32LittleEndian(b[(pos + 4)..]);
            long size = BinaryPrimitives.ReadInt64LittleEndian(b[(pos + 8)..]);
            if (nameLen <= 0 || pos + 24 + nameLen > b.Length) break;
            var name = Encoding.Unicode.GetString(b.Slice(pos + 24, nameLen));
            // name looks like ":Zone.Identifier:$DATA"; "::$DATA" is the main stream
            if (name != "::$DATA")
            {
                var clean = name.StartsWith(':') ? name[1..] : name;
                if (clean.EndsWith(":$DATA", StringComparison.Ordinal)) clean = clean[..^6];
                (list ??= new()).Add(new StreamEntry { Name = clean, Size = size });
            }
            if (next == 0) break;
            pos += next;
        }
        if (list != null) node.EnsureExtra().Streams = list;
    }

    private void ReadObjectId(SafeFileHandle h, ScanNode node)
    {
        fixed (byte* p = _small)
        {
            if (DeviceIoControl(h, FSCTL_GET_OBJECT_ID, IntPtr.Zero, 0, p, 64, out int got, IntPtr.Zero) && got >= 16)
                node.EnsureExtra().ObjectId = new Guid(_small.AsSpan(0, 16));
        }
    }

    private void ReadReparse(SafeFileHandle h, ScanNode node)
    {
        int got;
        fixed (byte* p = _reparseBuf)
        {
            if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, p, _reparseBuf.Length, out got, IntPtr.Zero) || got < 8)
            {
                node.EnsureExtra().Reparse = new ReparseInfo { Tag = 0 };
                return;
            }
        }
        node.EnsureExtra().Reparse = ParseReparse(_reparseBuf.AsSpan(0, got));
    }

    public static ReparseInfo ParseReparse(ReadOnlySpan<byte> b)
    {
        uint tag = BinaryPrimitives.ReadUInt32LittleEndian(b);
        int dataLen = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
        var data = b.Slice(8, Math.Min(dataLen, b.Length - 8));
        string? sub = null, print = null, extra = null;
        try
        {
            if (tag == 0xA0000003 || tag == 0xA000000C) // mount point / symlink
            {
                int so = BinaryPrimitives.ReadUInt16LittleEndian(data);
                int sl = BinaryPrimitives.ReadUInt16LittleEndian(data[2..]);
                int po = BinaryPrimitives.ReadUInt16LittleEndian(data[4..]);
                int pl = BinaryPrimitives.ReadUInt16LittleEndian(data[6..]);
                int baseOff = tag == 0xA000000C ? 12 : 8;
                if (tag == 0xA000000C)
                {
                    uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
                    if ((flags & 1) != 0) extra = "relative";
                }
                sub = Encoding.Unicode.GetString(data.Slice(baseOff + so, sl));
                print = Encoding.Unicode.GetString(data.Slice(baseOff + po, pl));
            }
            else if (tag == 0x8000001B) // AppExecLink: version, then NUL-separated strings
            {
                var s = Encoding.Unicode.GetString(data[4..]).Split('\0', StringSplitOptions.RemoveEmptyEntries);
                if (s.Length >= 3) { print = s[2]; extra = $"package {s[0]}, app {s[1]}"; }
                else extra = string.Join(" | ", s);
            }
            else if (tag == 0xA000001D) // WSL symlink: version + UTF-8 target
            {
                print = Encoding.UTF8.GetString(data[4..]);
            }
        }
        catch { /* keep the tag even if the payload is odd */ }
        return new ReparseInfo { Tag = tag, SubstituteName = sub, PrintName = print, Extra = extra };
    }

    /// <summary>Lists a directory through a backup-semantics handle. Returns the Win32 error (0 = ok).</summary>
    public int ListDirectory(string path, List<DirEntry> output)
    {
        output.Clear();
        using var h = CreateFileW(Long(path), FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, IntPtr.Zero);
        if (h.IsInvalid) return Marshal.GetLastWin32Error();
        bool first = true;
        while (true)
        {
            bool ok;
            fixed (byte* p = _dirBuf)
                ok = GetFileInformationByHandleEx(h, first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo, p, _dirBuf.Length);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                return err == 18 /*ERROR_NO_MORE_FILES*/ ? 0 : err;
            }
            first = false;
            ParseDir(output);
        }
    }

    private void ParseDir(List<DirEntry> output)
    {
        var b = _dirBuf.AsSpan();
        int pos = 0;
        while (true)
        {
            int next = BinaryPrimitives.ReadInt32LittleEndian(b[pos..]);
            long created = BinaryPrimitives.ReadInt64LittleEndian(b[(pos + 8)..]);
            long eof = BinaryPrimitives.ReadInt64LittleEndian(b[(pos + 40)..]);
            uint attr = BinaryPrimitives.ReadUInt32LittleEndian(b[(pos + 56)..]);
            int nameLen = BinaryPrimitives.ReadInt32LittleEndian(b[(pos + 60)..]);
            int shortLen = b[pos + 68];
            var name = Encoding.Unicode.GetString(b.Slice(pos + 104, nameLen));
            if (name != "." && name != "..")
            {
                string? shortName = shortLen > 0 ? Encoding.Unicode.GetString(b.Slice(pos + 70, Math.Min(shortLen, 24))) : null;
                output.Add(new DirEntry { Name = name, ShortName = shortName, Attributes = attr, Size = eof, Created = created });
            }
            if (next == 0) break;
            pos += next;
        }
    }
}

/// <summary>On-demand reads for the details panel (live machine only).</summary>
public static unsafe class LiveReads
{
    public static string ReadStreamText(string path, string stream, int maxBytes, out bool truncated, out bool binary)
    {
        truncated = false; binary = false;
        using var h = CreateFileW(FileProbe.Long(path) + ":" + stream, GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
        if (h.IsInvalid) return $"(could not open: error {Marshal.GetLastWin32Error()})";
        var buf = new byte[maxBytes + 1];
        int total = 0;
        fixed (byte* p = buf)
        {
            while (total < buf.Length && ReadFile(h, p + total, buf.Length - total, out int n, IntPtr.Zero) && n > 0) total += n;
        }
        if (total > maxBytes) { truncated = true; total = maxBytes; }
        var span = buf.AsSpan(0, total);
        if (LooksLikeText(span, out var text)) return text;
        binary = true;
        return HexDump(span, 512);
    }

    private static bool LooksLikeText(ReadOnlySpan<byte> b, out string text)
    {
        text = "";
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) { text = Encoding.Unicode.GetString(b[2..]); return true; }
        int ctrl = 0;
        foreach (var c in b) if (c < 9 || (c > 13 && c < 32)) ctrl++;
        if (b.Length > 0 && ctrl * 20 > b.Length) return false;
        text = Encoding.UTF8.GetString(b);
        return true;
    }

    public static string HexDump(ReadOnlySpan<byte> b, int max)
    {
        var sb = new StringBuilder();
        int n = Math.Min(b.Length, max);
        for (int i = 0; i < n; i += 16)
        {
            sb.Append(i.ToString("x4")).Append("  ");
            for (int j = 0; j < 16; j++) sb.Append(i + j < n ? b[i + j].ToString("x2") + " " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < n; j++) { var c = (char)b[i + j]; sb.Append(c >= 32 && c < 127 ? c : '.'); }
            sb.AppendLine();
        }
        if (b.Length > max) sb.AppendLine($"… {b.Length - max} more bytes");
        return sb.ToString();
    }

    /// <summary>NTFS time stamps of an object (FileBasicInfo): created, last written, and the change time — NTFS sets
    /// that one whenever anything in the object's metadata changes, its security descriptor included. Null if unreadable.</summary>
    public static (DateTime Created, DateTime Written, DateTime Changed)? Times(string path)
    {
        using var h = CreateFileW(FileProbe.Long(path), FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, IntPtr.Zero);
        if (h.IsInvalid) return null;
        byte* b = stackalloc byte[40];
        if (!GetFileInformationByHandleEx(h, 0 /* FileBasicInfo */, b, 40)) return null;
        static DateTime T(long v) => v <= 0 ? DateTime.MinValue : DateTime.FromFileTimeUtc(v).ToLocalTime();
        return (T(*(long*)b), T(*(long*)(b + 16)), T(*(long*)(b + 24)));
    }

    /// <summary>The first bytes of a file's main stream (backup semantics, so protected files can be read by an admin).</summary>
    public static byte[]? ReadBytes(string path, int maxBytes)
    {
        using var h = CreateFileW(FileProbe.Long(path), GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
        if (h.IsInvalid) return null;
        var buf = new byte[maxBytes];
        int total = 0;
        fixed (byte* p = buf)
            while (total < buf.Length && ReadFile(h, p + total, buf.Length - total, out int n, IntPtr.Zero) && n > 0) total += n;
        return buf.AsSpan(0, total).ToArray();
    }

    /// <summary>All names of a hard-linked file.</summary>
    public static List<string> HardLinkNames(string path)
    {
        var result = new List<string>();
        var buf = new char[32768];
        uint len = (uint)buf.Length;
        string volume = Path.GetPathRoot(path) ?? "";
        fixed (char* p = buf)
        {
            var h = FindFirstFileNameW(FileProbe.Long(path), 0, ref len, p);
            if (h == new IntPtr(-1)) return result;
            try
            {
                do
                {
                    result.Add(volume.TrimEnd('\\') + new string(p, 0, (int)Math.Max(0, len - 1)));
                    len = (uint)buf.Length;
                } while (FindNextFileNameW(h, ref len, p));
            }
            finally { FindClose(h); }
        }
        return result;
    }
}
