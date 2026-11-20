using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using AclLegibility.Model;
using AclLegibility.Security;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Native;

/// <summary>SID ⇄ account name lookups with a cache.</summary>
public static unsafe class SidResolver
{
    private static readonly ConcurrentDictionary<string, PrincipalName> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static PrincipalName Resolve(string sid)
    {
        if (Cache.TryGetValue(sid, out var cached)) return cached;
        var result = new PrincipalName { Sid = sid, Use = SidUse.Unresolved };
        var bin = SidText.ToBinary(sid);
        if (bin != null && OperatingSystem.IsWindows())
        {
            int cchName = 256, cchDomain = 256;
            char* name = stackalloc char[256];
            char* domain = stackalloc char[256];
            if (LookupAccountSidW(null, bin, name, ref cchName, domain, ref cchDomain, out int use))
            {
                result.Name = new string(name, 0, cchName);
                result.Domain = cchDomain > 0 ? new string(domain, 0, cchDomain) : null;
                result.Use = (SidUse)use;
            }
            else result.LookupError = Marshal.GetLastWin32Error();
        }
        Cache[sid] = result;
        return result;
    }

    public static string? SidOfAccount(string account)
    {
        int cbSid = 256, cchDomain = 256;
        byte* sid = stackalloc byte[256];
        char* domain = stackalloc char[256];
        if (!LookupAccountNameW(null, account, sid, ref cbSid, domain, ref cchDomain, out _)) return null;
        return SidText.FromBinary(new ReadOnlySpan<byte>(sid, cbSid), out _);
    }

    public static string? SidFromPointer(IntPtr psid)
    {
        if (psid == IntPtr.Zero) return null;
        if (!ConvertSidToStringSidW(psid, out var s)) return null;
        try { return Marshal.PtrToStringUni(s); }
        finally { LocalFree(s); }
    }
}
