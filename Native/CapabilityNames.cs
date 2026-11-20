using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using AclLegibility.Model;

namespace AclLegibility.Native;

/// <summary>
/// Gives names to capability SIDs (S-1-15-3-1024-…). Windows derives them from capability names with a
/// hash, so they cannot be looked up — but the same derivation can be run forwards for known names and the
/// results matched. Names that are not in the list keep showing as "Capability (named)".
/// </summary>
public static class CapabilityNames
{
    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool DeriveCapabilitySidsFromName(string capName, out IntPtr capabilityGroupSids, out uint capabilityGroupSidCount,
        out IntPtr capabilitySids, out uint capabilitySidCount);

    /// <summary>Known capability names: app capabilities, restricted capabilities and the lpac* set Windows grants on system files.</summary>
    private static readonly string[] Known =
    {
        // less-privileged app containers (granted on many system files)
        "lpacAppExperience", "lpacAppServices", "lpacClipboard", "lpacCom", "lpacCryptoServices", "lpacDeviceAccess",
        "lpacEnterprisePolicyChangeNotifications", "lpacIdentityServices", "lpacIME", "lpacInstrumentation", "lpacMedia",
        "lpacPackageManagerOperation", "lpacPayments", "lpacPnPNotifications", "lpacPnpNotifications", "lpacPrinting",
        "lpacServicesManagement", "lpacSessionManagement", "lpacWebPlatform", "lpacAuthentication", "lpacFileSystem",
        "lpacTelemetry", "lpacSpeech",
        "registryRead",
        // general / restricted capabilities
        "internetClient", "internetClientServer", "privateNetworkClientServer", "enterpriseAuthentication", "sharedUserCertificates",
        "documentsLibrary", "picturesLibrary", "videosLibrary", "musicLibrary", "removableStorage", "objects3D",
        "appointments", "contacts", "location", "webcam", "microphone", "bluetooth", "proximity", "humaninterfacedevice",
        "userAccountInformation", "phoneCall", "phoneCallHistory", "phoneCallHistoryPublic", "chat", "blockedChatMessages",
        "lowLevelDevices", "lowLevel", "runFullTrust", "allowElevation", "broadFileSystemAccess", "packageManagement", "packageQuery",
        "appDiagnostics", "inputInjectionBrokered", "inputInjection", "userDataTasks", "userNotificationListener", "backgroundMediaPlayback",
        "backgroundMediaRecording", "offlineMapsManagement", "remoteSystem", "spatialPerception", "systemManagement", "gazeInput",
        "graphicsCapture", "graphicsCaptureProgrammatic", "graphicsCaptureWithoutBorder", "globalMediaControl", "cellularDeviceIdentity",
        "deviceUnlock", "previewStore", "confirmAppClose", "extendedExecutionUnconstrained", "extendedBackgroundTaskTime",
        "unvirtualizedResources", "packagedServices", "localSystemServices", "smbios", "cortanaPermissions", "developmentModeNetwork",
        "dualSimTiles", "enterpriseDataPolicy", "enterpriseDeviceLockdown", "inputForegroundObservation", "inputSuppression",
        "inputObservation", "oemDeployment", "oneProcessVoip", "slapiQueryLicenseValue", "teamEditionExperience", "userPrincipalName",
        "userSigninSupport", "walletSystem", "xboxAccessoryManagement", "uiAutomation", "accessoryManager", "activity",
        "cameraProcessingExtension", "constrainedImpersonation", "coreShell", "expandedResources", "userDataSystem", "userSystemId",
        "voipCall", "recordedCallsFolder", "networkConnectionManagerProvisioning", "networkDataPlanProvisioning", "networkingVpnProvider",
        "cellularMessaging", "secondaryAuthenticationFactor", "screenDuplication", "allJoyn", "codeGeneration", "gameList",
        "gameBarServices", "appCaptureSettings", "appCaptureServices", "appBroadcastServices", "audioDeviceConfiguration",
        "backgroundSpatialPerception", "emailSystem", "email", "enterpriseCloudSSO", "firstSignInSettings", "hevcPlayback",
        "interopServices", "locationHistory", "locationSystem", "modifiableApp", "optical", "perceptionSensorsExperimental",
        "protectedApp", "remotePassportAuthentication", "serialcommunication", "shellExperience", "storeLicenseManagement",
        "targetedContent", "uiAccess", "unvirtualizedResources", "usb", "userDataAccountsProvider", "wiFiControl", "radios",
        "pointOfService", "sensors.custom", "systemDialog", "deviceManagementDmAccount", "deviceManagementFoundation",
        "deviceManagementWapSecurityPolicies", "deviceManagementEmailAccount", "deviceManagementAdministrator", "deviceManagementRegistration",
        "liveIdService", "cloudStore", "webPlatformMediaExtension", "isolatedWin32-print", "isolatedWin32-promptForAccess",
        "isolatedWin32-userProfileMinimal", "isolatedWin32-accessToPublisherDirectory", "isolatedWin32-dotNetBreadcrumbStore",
        "isolatedWin32-profilesRootMinimal", "isolatedWin32-shellExtensionContextMenu", "isolatedWin32-sysTrayIcon",
        "isolatedWin32-volumeRootMinimal", "packageContents", "applicationDefaults", "audioDeviceConfiguration",
    };

    private static Dictionary<string, string>? _map;
    private static readonly object Lock = new();

    /// <summary>SID → capability name for every known name (computed once; empty off Windows).</summary>
    public static IReadOnlyDictionary<string, string> Map
    {
        get
        {
            lock (Lock)
            {
                if (_map != null) return _map;
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (OperatingSystem.IsWindows())
                {
                    foreach (var name in Known)
                    {
                        try { foreach (var sid in Derive(name)) map.TryAdd(sid, name); }
                        catch { /* missing on very old builds: keep what we have */ }
                    }
                }
                return _map = map;
            }
        }
    }

    private static List<string> Derive(string name)
    {
        var result = new List<string>();
        if (!DeriveCapabilitySidsFromName(name, out var groups, out var groupCount, out var caps, out var capCount)) return result;
        try
        {
            for (int i = 0; i < capCount; i++)
                if (SidResolver.SidFromPointer(Marshal.ReadIntPtr(caps, i * IntPtr.Size)) is { } s) result.Add(s);
        }
        finally
        {
            Free(groups, groupCount);
            Free(caps, capCount);
        }
        return result;
    }

    private static void Free(IntPtr array, uint count)
    {
        if (array == IntPtr.Zero) return;
        for (int i = 0; i < count; i++) NativeMethods.LocalFree(Marshal.ReadIntPtr(array, i * IntPtr.Size));
        NativeMethods.LocalFree(array);
    }

    /// <summary>Names every capability SID in the result that Windows could not resolve.</summary>
    public static void Fill(ScanResult result)
    {
        var map = Map;
        if (map.Count == 0) return;
        foreach (var sid in new List<string>(result.Names.Keys))
        {
            if (!sid.StartsWith("S-1-15-3-", StringComparison.Ordinal)) continue;
            var p = result.Names[sid];
            if (p.Resolved) continue;
            if (map.TryGetValue(sid, out var name))
                result.Names[sid] = new PrincipalName { Sid = sid, Domain = "Capability", Name = name, Use = SidUse.WellKnownGroup };
        }
    }
}
