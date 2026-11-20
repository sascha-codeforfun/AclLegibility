using System;
using System.Collections.Generic;
namespace AclLegibility.Model;

public sealed class OsInfo
{
    public string ProductName { get; set; } = "";
    public string EditionId { get; set; } = "";
    public string DisplayVersion { get; set; } = "";
    public int Major { get; set; }
    public int Minor { get; set; }
    public int Build { get; set; }
    public int Ubr { get; set; }
    public string InstallationType { get; set; } = "";   // Client, Server, Server Core
    public bool IsServer { get; set; }
    public string Architecture { get; set; } = "";
    public string UiLanguage { get; set; } = "";
    public string ComputerName { get; set; } = "";
    public string? MachineSid { get; set; }
    public bool DomainJoined { get; set; }
    public string? DomainName { get; set; }
    public string? DnsDomainName { get; set; }

    /// <summary>Well-known folder locations of the scanned machine, by variable name (no % signs).</summary>
    public Dictionary<string, string> Paths { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Windows' profile list: account SID → profile folder (ProfileList\&lt;SID&gt;\ProfileImagePath).</summary>
    public Dictionary<string, string> Profiles { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>When the current Windows was installed or last upgraded in place (CurrentVersion\InstallDate), UTC.</summary>
    public DateTime? CurrentInstallUtc { get; set; }
    /// <summary>Earlier Windows versions this installation was upgraded from (HKLM\SYSTEM\Setup\Source OS …), oldest first.</summary>
    public List<SourceOs> UpgradedFrom { get; set; } = new();

    /// <summary>win10, win11, srv2019, srv2025 — or null when this OS is not a tested target.</summary>
    public string? TargetKey
    {
        get
        {
            if (IsServer)
                return Build switch { 17763 => "srv2019", 26100 => "srv2025", _ => null };
            if (Major == 10 && Build >= 10240 && Build < 22000) return "win10";
            if (Major == 10 && Build >= 22000) return "win11";
            return null;
        }
    }

    /// <summary>Best guess of the family even for untested builds (used to pick knowledge entries).</summary>
    public string FamilyKey
    {
        get
        {
            if (TargetKey != null) return TargetKey;
            if (IsServer) return Build >= 26100 ? "srv2025" : Build >= 20348 ? "srv2022" : "srv2019";
            return Build >= 22000 ? "win11" : "win10";
        }
    }

    public bool IsTestedTarget => TargetKey != null;

    public string FriendlyName
    {
        get
        {
            var name = ProductName;
            // Windows 11 still reports "Windows 10 ..." in ProductName.
            if (!IsServer && Build >= 22000 && name.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
                name = "Windows 11" + name[10..];
            return name;
        }
    }

    public string VersionLine =>
        $"{FriendlyName} {DisplayVersion}".Trim() + $" · build {Build}.{Ubr} · {InstallationType} · {Architecture}";
}

/// <summary>One earlier Windows of an installation upgraded in place, as Windows Setup keeps it.</summary>
public sealed class SourceOs
{
    public string Product { get; set; } = "";
    /// <summary>"23H2" etc., when the key has it.</summary>
    public string DisplayVersion { get; set; } = "";
    public int Build { get; set; }
    public int Ubr { get; set; }
    /// <summary>When that earlier Windows was installed (its InstallDate), UTC.</summary>
    public DateTime? InstalledUtc { get; set; }
    /// <summary>When Setup replaced it, as written in the key name ("Updated on …"), or null.</summary>
    public DateTime? ReplacedLocal { get; set; }

    /// <summary>Windows 11 keeps writing "Windows 10" as its product name (also here); build 22000 and later is Windows 11.</summary>
    public string FriendlyProduct =>
        Build >= 22000 && Product.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase) ? "Windows 11" + Product[10..] : Product;

    public string Describe() =>
        $"build {Build}.{Ubr}" + (Product.Length > 0 ? $" ({(FriendlyProduct + " " + DisplayVersion).Trim()})" : "")
        + (InstalledUtc is { } i ? $", installed {i.ToLocalTime():yyyy-MM-dd}" : "")
        + (ReplacedLocal is { } r ? $", upgraded on {r:yyyy-MM-dd}" : "");
}
