using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AclLegibility.Native;

/// <summary>All Win32 / NT imports used by the app. No third-party code.</summary>
internal static unsafe class NativeMethods
{
    // ---- CreateFile -------------------------------------------------------------------------
    public const uint READ_CONTROL = 0x00020000;
    public const uint ACCESS_SYSTEM_SECURITY = 0x01000000;
    public const uint FILE_READ_ATTRIBUTES = 0x0080;
    public const uint FILE_LIST_DIRECTORY = 0x0001;
    public const uint FILE_READ_DATA = 0x0001;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint GENERIC_READ = 0x80000000;

    public const uint FILE_SHARE_ALL = 0x1 | 0x2 | 0x4;
    public const uint OPEN_EXISTING = 3;

    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_FLAG_OPEN_NO_RECALL = 0x00100000;
    public const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    /// <summary>Asks Windows to hold a shutdown or sign-out and shows the reason on its "apps are preventing shutdown" screen.</summary>
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool ShutdownBlockReasonCreate(IntPtr hWnd, string reason);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool ShutdownBlockReasonDestroy(IntPtr hWnd);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    public const uint DELETE = 0x00010000;
    public const uint FILE_WRITE_ATTRIBUTES = 0x0100;
    public const int FileDispositionInfo = 4;
    public const int FileDispositionInfoEx = 21;
    public const uint FILE_DISPOSITION_FLAG_DELETE = 0x1, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x2,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x10;

    /// <summary>Deletes a user profile: its folder and its entry in Windows' profile list (as "Account Unknown → Delete" in
    /// System Properties). Fails for a loaded profile.</summary>
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool DeleteProfileW(string lpSidString, string? lpProfilePath, string? lpComputerName);

    /// <summary>Space a file really takes on disk (compressed or sparse files take less than their size).</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFileInformationByHandle(SafeFileHandle hFile, int fileInformationClass, ref uint info, int size);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    public static extern bool SetFileInformationByHandlePtr(SafeFileHandle hFile, int fileInformationClass, byte* info, int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFileAttributesW(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(SafeFileHandle hFile, byte* lpBuffer, int nNumberOfBytesToRead, out int lpNumberOfBytesRead, IntPtr lpOverlapped);

    // ---- Security ---------------------------------------------------------------------------
    public const uint OWNER_SECURITY_INFORMATION = 0x1;
    public const uint GROUP_SECURITY_INFORMATION = 0x2;
    public const uint DACL_SECURITY_INFORMATION = 0x4;
    public const uint SACL_SECURITY_INFORMATION = 0x8;
    public const uint LABEL_SECURITY_INFORMATION = 0x10;

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetKernelObjectSecurity(SafeHandle handle, uint requestedInformation, byte* pSecurityDescriptor, int nLength, out int lpnLengthNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LookupAccountSidW(string? lpSystemName, byte[] sid, char* name, ref int cchName,
        char* referencedDomainName, ref int cchReferencedDomainName, out int peUse);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LookupAccountNameW(string? lpSystemName, string lpAccountName, byte* sid, ref int cbSid,
        char* referencedDomainName, ref int cchReferencedDomainName, out int peUse);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int GetLengthSid(IntPtr pSid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    // ---- Privileges -------------------------------------------------------------------------
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    public const uint TOKEN_QUERY = 0x8;
    public const uint SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES_1 { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES_1 newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    // ---- File information -------------------------------------------------------------------
    // Pack = 4 is required: Windows declares the times as FILETIME (two DWORDs, 4-byte aligned). With the default
    // 8-byte alignment of long, .NET inserted 4 bytes after FileAttributes, every later field shifted, and
    // NumberOfLinks read the upper half of the file ID (0.1.0–0.1.6 bug: millions of "hard links" per file).
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh, FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION info);

    public const int FileIdBothDirectoryInfo = 10;
    public const int FileIdBothDirectoryRestartInfo = 11;
    public const int FileCaseSensitiveInfo = 23;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandleEx(SafeFileHandle hFile, int infoClass, byte* buffer, int bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindFirstFileNameW(string lpFileName, uint dwFlags, ref uint stringLength, char* linkName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool FindNextFileNameW(IntPtr hFindStream, ref uint stringLength, char* linkName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FindClose(IntPtr hFindFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool GetVolumePathNameW(string lpszFileName, char* lpszVolumePathName, int cchBufferLength);

    // ---- DeviceIoControl --------------------------------------------------------------------
    public const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
    public const uint FSCTL_GET_OBJECT_ID = 0x0009009C;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr inBuffer, int nInBufferSize,
        byte* outBuffer, int nOutBufferSize, out int bytesReturned, IntPtr overlapped);

    // ---- NT ---------------------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    public const int FileStreamInformation = 22;
    public const int STATUS_SUCCESS = 0;
    public const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);
    public const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
    public const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationFile(SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock,
        byte* fileInformation, int length, int fileInformationClass);

    [DllImport("ntdll.dll")]
    public static extern int RtlNtStatusToDosError(int status);

    // CharSet.Unicode is required: without it ByValTStr marshals 128 ANSI bytes instead of
    // 128 UTF-16 chars, every later field shifts, and wProductType reads garbage (0.1.1 bug:
    // a client was reported as a server).
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion;
        public ushort wServicePackMajor, wServicePackMinor, wSuiteMask;
        public byte wProductType, wReserved;
    }

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    public static extern int RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

    // ---- netapi32 ---------------------------------------------------------------------------
    public const int MAX_PREFERRED_LENGTH = -1;
    public const int NERR_Success = 0;
    public const int ERROR_MORE_DATA = 234;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareEnum(string? serverName, int level, out IntPtr bufPtr, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserEnum(string? serverName, int level, int filter, out IntPtr bufPtr, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupEnum(string? serverName, int level, out IntPtr bufPtr, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level, out IntPtr bufPtr,
        int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetGetJoinInformation(string? server, out IntPtr nameBuffer, out int bufferType);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_502
    {
        public IntPtr netname;
        public uint type;
        public IntPtr remark;
        public uint permissions;
        public uint max_uses;
        public uint current_uses;
        public IntPtr path;
        public IntPtr passwd;
        public uint reserved;
        public IntPtr security_descriptor;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        public IntPtr name;
        public IntPtr password;
        public uint password_age;
        public uint priv;
        public IntPtr home_dir;
        public IntPtr comment;
        public uint flags;
        public IntPtr script_path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_INFO_1 { public IntPtr name; public IntPtr comment; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr sid; public int sidusage; public IntPtr domainandname; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

    // ---- writing (permission actions) -----------------------------------------------------------
    public const int SE_FILE_OBJECT = 1;
    public const uint UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;
    public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
    public const int ACL_REVISION = 2;

    /// <summary>Sets the DACL by name. With UNPROTECTED_DACL_SECURITY_INFORMATION Windows recomputes the
    /// inherited entries from the parent and propagates inheritable changes to children. Returns a Win32 error.</summary>
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfoW(string pObjectName, int objectType, uint securityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool InitializeAcl(IntPtr pAcl, int nAclLength, int dwAclRevision);
}
