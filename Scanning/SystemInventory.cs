using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using AclLegibility.Model;
using AclLegibility.Native;
using AclLegibility.Security;
using Microsoft.Win32;
using static AclLegibility.Native.NativeMethods;

namespace AclLegibility.Scanning;

/// <summary>OS facts, local accounts, groups and shares of the running machine.</summary>
public static class SystemInventory
{
    public static OsInfo DetectOs()
    {
        var os = new OsInfo();
        try
        {
            var v = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf<OSVERSIONINFOEXW>(), szCSDVersion = "" };
            if (RtlGetVersion(ref v) == 0)
            {
                os.Major = v.dwMajorVersion; os.Minor = v.dwMinorVersion; os.Build = v.dwBuildNumber;
                os.IsServer = v.wProductType != 1; // VER_NT_WORKSTATION
            }
        }
        catch { }
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (k != null)
            {
                os.ProductName = k.GetValue("ProductName") as string ?? "";
                os.EditionId = k.GetValue("EditionID") as string ?? "";
                os.DisplayVersion = k.GetValue("DisplayVersion") as string ?? k.GetValue("ReleaseId") as string ?? "";
                os.InstallationType = k.GetValue("InstallationType") as string ?? (os.IsServer ? "Server" : "Client");
                if (k.GetValue("UBR") is int ubr) os.Ubr = ubr;
                if (k.GetValue("InstallDate") is int idate && idate > 0) os.CurrentInstallUtc = DateTimeOffset.FromUnixTimeSeconds((uint)idate).UtcDateTime;
                if (os.Build == 0 && int.TryParse(k.GetValue("CurrentBuildNumber") as string, out var b)) os.Build = b;
            }
        }
        catch { }
        os.Architecture = RuntimeInformation.OSArchitecture.ToString();
        os.UiLanguage = System.Globalization.CultureInfo.InstalledUICulture.Name;
        os.ComputerName = Environment.MachineName;
        os.MachineSid = MachineSid(os.ComputerName);

        try
        {
            if (NetGetJoinInformation(null, out var nameBuf, out int type) == NERR_Success)
            {
                try
                {
                    if (type == 3) // NetSetupDomainName
                    {
                        os.DomainJoined = true;
                        os.DomainName = Marshal.PtrToStringUni(nameBuf);
                    }
                }
                finally { NetApiBufferFree(nameBuf); }
            }
        }
        catch { }
        if (os.DomainJoined)
        {
            try { os.DnsDomainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName; } catch { }
        }

        void P(string key, string? value) { if (!string.IsNullOrEmpty(value)) os.Paths[key] = value.TrimEnd('\\'); }
        P("SystemDrive", Environment.GetEnvironmentVariable("SystemDrive"));
        P("SystemRoot", Environment.GetEnvironmentVariable("SystemRoot"));
        P("windir", Environment.GetEnvironmentVariable("windir"));
        P("ProgramFiles", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        P("ProgramFiles(x86)", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        P("ProgramData", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        P("PUBLIC", Environment.GetEnvironmentVariable("PUBLIC"));
        try
        {
            using var pl = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (pl?.GetValue("ProfilesDirectory") is string pd) P("ProfilesDir", Environment.ExpandEnvironmentVariables(pd));
            if (pl?.GetValue("Default") is string def) P("DefaultProfile", Environment.ExpandEnvironmentVariables(def));
            if (pl != null)
                foreach (var sid in pl.GetSubKeyNames())
                {
                    using var k = pl.OpenSubKey(sid);
                    if (k?.GetValue("ProfileImagePath") is string img && img.Length > 0)
                        os.Profiles[sid] = Environment.ExpandEnvironmentVariables(img).TrimEnd('\\');
                }
        }
        catch { }
        if (!os.Paths.ContainsKey("ProfilesDir") && os.Paths.TryGetValue("SystemDrive", out var sd)) os.Paths["ProfilesDir"] = sd + @"\Users";
        try { os.UpgradedFrom = SourceOsList(); } catch { }
        return os;
    }

    /// <summary>Windows Setup keeps one "Source OS (Updated on …)" key per in-place upgrade under HKLM\SYSTEM\Setup.</summary>
    private static List<SourceOs> SourceOsList()
    {
        var list = new List<SourceOs>();
        using var setup = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup");
        if (setup == null) return list;
        foreach (var name in setup.GetSubKeyNames())
        {
            if (!name.StartsWith("Source OS", StringComparison.OrdinalIgnoreCase)) continue;
            using var k = setup.OpenSubKey(name);
            if (k == null) continue;
            var e = new SourceOs { Product = k.GetValue("ProductName") as string ?? "", DisplayVersion = k.GetValue("DisplayVersion") as string ?? "" };
            if (int.TryParse(k.GetValue("CurrentBuild") as string ?? k.GetValue("CurrentBuildNumber") as string, out var b)) e.Build = b;
            if (k.GetValue("UBR") is int ubr) e.Ubr = ubr;
            if (k.GetValue("InstallDate") is int idate && idate > 0) e.InstalledUtc = DateTimeOffset.FromUnixTimeSeconds((uint)idate).UtcDateTime;
            var open = name.IndexOf("Updated on ", StringComparison.OrdinalIgnoreCase);
            if (open >= 0)
            {
                var text = name[(open + 11)..].TrimEnd(')', ' ');
                if (DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var when))
                    e.ReplacedLocal = when;
            }
            list.Add(e);
        }
        list.Sort((a, b) => Nullable.Compare(a.InstalledUtc, b.InstalledUtc));
        return list;
    }

    private static string? MachineSid(string computerName)
    {
        try { return SidResolver.SidOfAccount(computerName); } catch { return null; }
    }

    public static Inventory Collect()
    {
        var inv = new Inventory();
        try { inv.Users = Users(); } catch (Exception ex) { inv.Notes.Add("Local users: " + ex.Message); }
        try { inv.Groups = Groups(); } catch (Exception ex) { inv.Notes.Add("Local groups: " + ex.Message); }
        try { inv.Shares = Shares(); } catch (Exception ex) { inv.Notes.Add("Shares: " + ex.Message); }
        try { inv.AccountTraces = AccountTraces(); } catch (Exception ex) { inv.Notes.Add("Account records: " + ex.Message); }
        return inv;
    }

    /// <summary>Account SIDs recorded by User Manager and by the app store's per-account keys (read only).</summary>
    private static Dictionary<string, List<string>> AccountTraces()
    {
        var traces = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string? sid, string where)
        {
            if (string.IsNullOrEmpty(sid) || SidText.SplitAccountSid(sid) == null) return;
            if (!traces.TryGetValue(sid, out var list)) traces[sid] = list = new();
            if (!list.Contains(where)) list.Add(where);
        }
        using (var um = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\UserManager\Users"))
            if (um != null)
                foreach (var name in um.GetSubKeyNames())
                {
                    using var k = um.OpenSubKey(name);
                    Add(k?.GetValue("Sid") as string, @"User Manager record (HKLM\SOFTWARE\Microsoft\UserManager\Users\" + name + ")");
                }
        using (var store = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"))
            if (store != null)
                foreach (var name in store.GetSubKeyNames())
                    Add(name, @"app store key (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\" + name + ")");
        return traces;
    }

    private static List<LocalUser> Users()
    {
        var list = new List<LocalUser>();
        int resume = 0;
        int rc;
        do
        {
            rc = NetUserEnum(null, 1, 0x2 /*FILTER_NORMAL_ACCOUNT*/, out var buf, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            if (rc != NERR_Success && rc != ERROR_MORE_DATA) break;
            try
            {
                int size = Marshal.SizeOf<USER_INFO_1>();
                for (int i = 0; i < read; i++)
                {
                    var u = Marshal.PtrToStructure<USER_INFO_1>(buf + i * size);
                    var name = Marshal.PtrToStringUni(u.name) ?? "";
                    list.Add(new LocalUser
                    {
                        Name = name,
                        Comment = Marshal.PtrToStringUni(u.comment),
                        Flags = u.flags,
                        Sid = SidResolver.SidOfAccount(Environment.MachineName + "\\" + name),
                    });
                }
            }
            finally { NetApiBufferFree(buf); }
        } while (rc == ERROR_MORE_DATA);
        return list;
    }

    private static List<LocalGroup> Groups()
    {
        var list = new List<LocalGroup>();
        IntPtr resume = IntPtr.Zero;
        int rc;
        do
        {
            rc = NetLocalGroupEnum(null, 1, out var buf, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            if (rc != NERR_Success && rc != ERROR_MORE_DATA) break;
            try
            {
                int size = Marshal.SizeOf<LOCALGROUP_INFO_1>();
                for (int i = 0; i < read; i++)
                {
                    var g = Marshal.PtrToStructure<LOCALGROUP_INFO_1>(buf + i * size);
                    var name = Marshal.PtrToStringUni(g.name) ?? "";
                    var lg = new LocalGroup { Name = name, Comment = Marshal.PtrToStringUni(g.comment) };
                    lg.Sid = SidResolver.SidOfAccount(name);
                    lg.Members = Members(name);
                    list.Add(lg);
                }
            }
            finally { NetApiBufferFree(buf); }
        } while (rc == ERROR_MORE_DATA);
        return list;
    }

    private static List<GroupMember> Members(string group)
    {
        var list = new List<GroupMember>();
        IntPtr resume = IntPtr.Zero;
        int rc;
        do
        {
            rc = NetLocalGroupGetMembers(null, group, 2, out var buf, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            if (rc != NERR_Success && rc != ERROR_MORE_DATA) break;
            try
            {
                int size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
                for (int i = 0; i < read; i++)
                {
                    var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buf + i * size);
                    list.Add(new GroupMember
                    {
                        Sid = SidResolver.SidFromPointer(m.sid) ?? "",
                        Name = Marshal.PtrToStringUni(m.domainandname) ?? "",
                        Use = (SidUse)m.sidusage,
                    });
                }
            }
            finally { NetApiBufferFree(buf); }
        } while (rc == ERROR_MORE_DATA);
        return list;
    }

    private static List<ShareEntry> Shares()
    {
        var list = new List<ShareEntry>();
        int resume = 0;
        int rc;
        do
        {
            rc = NetShareEnum(null, 502, out var buf, MAX_PREFERRED_LENGTH, out int read, out _, ref resume);
            if (rc != NERR_Success && rc != ERROR_MORE_DATA) break;
            try
            {
                int size = Marshal.SizeOf<SHARE_INFO_502>();
                for (int i = 0; i < read; i++)
                {
                    var s = Marshal.PtrToStructure<SHARE_INFO_502>(buf + i * size);
                    byte[]? sd = null;
                    if (s.security_descriptor != IntPtr.Zero)
                    {
                        int len = GetSecurityDescriptorLength(s.security_descriptor);
                        if (len > 0) { sd = new byte[len]; Marshal.Copy(s.security_descriptor, sd, 0, len); }
                    }
                    list.Add(new ShareEntry
                    {
                        Name = Marshal.PtrToStringUni(s.netname) ?? "",
                        Path = Marshal.PtrToStringUni(s.path),
                        Type = s.type,
                        Remark = Marshal.PtrToStringUni(s.remark),
                        SecurityDescriptor = sd,
                    });
                }
            }
            finally { NetApiBufferFree(buf); }
        } while (rc == ERROR_MORE_DATA);
        return list;
    }
}
