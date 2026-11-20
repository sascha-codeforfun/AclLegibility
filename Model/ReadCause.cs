using System;

namespace AclLegibility.Model;

/// <summary>Why an object could not be read, grouped from the Windows error code.</summary>
public enum ReadCause { InUse, Denied, Gone, PathName, Cloud, Device, NotSupported, Other }

public static class ReadCauses
{
    public static ReadCause Of(int code) => code switch
    {
        32 or 33 => ReadCause.InUse,                       // sharing / lock violation
        5 or 1314 => ReadCause.Denied,                     // access denied, privilege not held
        2 or 3 or 1005 or 1617 => ReadCause.Gone,          // file/path not found, volume gone
        206 or 123 or 161 or 1921 => ReadCause.PathName,   // name too long, invalid name, bad path
        >= 358 and <= 404 => ReadCause.Cloud,              // ERROR_CLOUD_FILE_* range
        4390 or 1920 => ReadCause.NotSupported,            // not a reparse point / file cannot be accessed by the system
        21 or 23 or 1117 or 1392 or 1393 or 483 => ReadCause.Device, // not ready, CRC, I/O, corrupt
        1 or 50 or 87 => ReadCause.NotSupported,           // invalid function, not supported, invalid parameter
        _ => ReadCause.Other,
    };

    public static string Label(ReadCause c) => c switch
    {
        ReadCause.InUse => "in use",
        ReadCause.Denied => "denied",
        ReadCause.Gone => "gone during scan",
        ReadCause.PathName => "path or name",
        ReadCause.Cloud => "cloud / offline",
        ReadCause.Device => "device or I/O",
        ReadCause.NotSupported => "not supported",
        _ => "other",
    };

    public static string Explain(ReadCause c) => c switch
    {
        ReadCause.InUse => "Another process holds the object open exclusively — typical for paging and hibernation files, open databases and logs of running services.",
        ReadCause.Denied => "Access was refused even with backup privilege — typically objects of protected processes, some driver stores, or objects whose DACL denies the backup operator path.",
        ReadCause.Gone => "The object disappeared while the scan was running — temporary files, caches, or a volume that went away.",
        ReadCause.PathName => "The path is too long for the API used or contains characters Windows does not accept in this form.",
        ReadCause.Cloud => "A cloud or offline placeholder whose provider is not running or refused the request. The scan never downloads content, so such objects can stay closed.",
        ReadCause.Device => "The storage reported an error — a failing disk, removable media, or file system corruption. Worth checking with chkdsk.",
        ReadCause.NotSupported => "The file system or a filter driver does not support this request — e.g. a reparse point the system itself cannot open, or a non-NTFS volume.",
        _ => "An error not grouped yet; the code is shown.",
    };

    /// <summary>Which step failed, from the stage recorded by the scanner.</summary>
    public static string Step(string? stage)
    {
        if (string.IsNullOrEmpty(stage)) return "could not be read";
        if (stage.StartsWith("list", StringComparison.Ordinal)) return "contents could not be listed";
        if (stage == "security") return "opened, but its permissions could not be read";
        if (stage == "open") return "could not be opened";
        return stage;
    }
}
