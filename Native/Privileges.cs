using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Native;

/// <summary>Enables the token privileges that let an elevated process read every security descriptor.</summary>
public static class Privileges
{
    public const string Backup = "SeBackupPrivilege";
    public const string Security = "SeSecurityPrivilege";
    /// <summary>Only enabled for Reset to inherit: lets the process change DACLs it could not otherwise open for writing.</summary>
    public const string Restore = "SeRestorePrivilege";
    /// <summary>Only enabled for orphan cleanup, together with Restore, to set a new owner.</summary>
    public const string TakeOwnership = "SeTakeOwnershipPrivilege";

    /// <summary>Returns the privileges that were enabled successfully.</summary>
    public static IReadOnlyList<string> EnableReadPrivileges()
    {
        var enabled = new List<string>();
        foreach (var name in new[] { Backup, Security })
            if (Enable(name)) enabled.Add(name);
        return enabled;
    }

    public static bool Enable(string privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            return false;
        using (token)
        {
            if (!LookupPrivilegeValueW(null, privilege, out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES_1 { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            // AdjustTokenPrivileges returns true with ERROR_NOT_ALL_ASSIGNED (1300) when the token lacks it.
            return Marshal.GetLastWin32Error() == 0;
        }
    }
}
