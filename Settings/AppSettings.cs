using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace AclLegibility.Settings;

/// <summary>AclLegibility.json next to the exe (HueTheme rule 15). Created with defaults on first run;
/// a settings.json from 0.1.x is taken over once.</summary>
public sealed class AppSettings
{
    /// <summary>Mask computer, domain and user names in "Copy for AI" output by default.</summary>
    public bool MaskByDefault { get; set; } = true;

    /// <summary>Accounts that are never masked; shown by name only (no SID), with their groups.</summary>
    public List<string> UnmaskedAccounts { get; set; } = new();

    /// <summary>Upper bound on items in one export (the rest is summarised by count).</summary>
    public int ExportMaxItems { get; set; } = 2000;

    /// <summary>Busy rings: true = always turn ("Override system setting (always turn)"),
    /// null = follow Windows' animation setting, false = never turn.</summary>
    public bool? AnimateOverride { get; set; } = true;

    /// <summary>Folder of the exe (not the single-file extraction folder).</summary>
    public static string AppFolder =>
        Path.GetDirectoryName(Environment.ProcessPath) is { Length: > 0 } dir ? dir : AppContext.BaseDirectory;

    public static string FilePath => Path.Combine(AppFolder, "AclLegibility.json");
    private static string LegacyFilePath => Path.Combine(AppFolder, "settings.json");
    public static string UserKnowledgePath => Path.Combine(AppFolder, "knowledge.user.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static AppSettings Load(out string? message)
    {
        message = null;
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
            var s = File.Exists(LegacyFilePath)
                ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(LegacyFilePath), Options) ?? new AppSettings()
                : new AppSettings();
            // Folder not writable: keep the settings for this session and carry on (rule 15).
            try
            {
                File.WriteAllText(FilePath, JsonSerializer.Serialize(s, Options));
                if (File.Exists(LegacyFilePath)) File.Delete(LegacyFilePath);
            }
            catch { }
            return s;
        }
        catch (Exception ex)
        {
            message = "AclLegibility.json could not be read, defaults used: " + ex.Message;
            return new AppSettings();
        }
    }
}
