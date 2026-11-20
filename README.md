# AclLegibility 1.0.0

See every permission, stream and filesystem quirk on this machine, and what's stock versus custom.

## Before you build or run it

- **Needs administrator rights:** runs as administrator; Windows asks when it starts (`app.manifest`,
  `requireAdministrator`). It turns on backup and security privileges for itself only
  (`advapi32.dll › AdjustTokenPrivileges`, in `Native/Privileges.cs`).
- **Changes security settings:** only through actions you start yourself, each with a preview or a confirmation:
  - *Reset to inherit* — removes explicit entries below a folder on a drive other than the running Windows' drive.
    `advapi32.dll › SetNamedSecurityInfoW` (`Security/ResetToInherit.cs`), restore privilege on for the action.
  - *Clean up orphaned SIDs* — owners and entries of accounts that no longer exist, outside `%SystemRoot%`.
    `advapi32.dll › SetNamedSecurityInfoW` (`Security/OrphanCleanup.cs`), restore and take-ownership privileges on
    for the action. It also **deletes** leftover folders named after those accounts (`kernel32.dll › CreateFileW`
    with backup semantics, then `SetFileInformationByHandle` with a delete disposition) and their **profiles**
    (`userenv.dll › DeleteProfileW`, folder and profile-list entry), after offering to save personal files found in
    them as a ZIP (`System.IO.Compression`, read with backup semantics, verified). Inside `%SystemRoot%` it deletes
    single files only when a knowledge entry marked *removable* explains them as leftovers of the deleted account
    (in knowledge base v14: WDI StartupInfo files, `appcompat\Backup` records, `System32\LogFiles\setupcln` logs),
    and only the ones you tick (none is ticked by default).
  - *Undo Explorer grants* — removes the full-control entry Explorer's "Continue" button adds, outside
    `%SystemRoot%`. `advapi32.dll › SetNamedSecurityInfoW` (`Security/ExplorerGrants.cs`), restore and
    take-ownership privileges on for the action.
  - *Remove download marks* (details panel of a folder or drive, live scan) — deletes the `Zone.Identifier` stream
    (Mark of the Web) of the files you tick below it: `kernel32.dll › CreateFileW` on `file:Zone.Identifier` with
    backup semantics, then `SetFileInformationByHandle` with a delete disposition that ignores read-only (`Security/DownloadMarks.cs`),
    restore privilege on for the action. The file's time stamps are read before and written back after
    (`FileBasicInfo`); content, other streams, security and object ID are not touched.
- **Changes the whole computer:** only through actions you start yourself, each with a preview or a confirmation:
  - *Component store clean-up* (button in the action row, also in the details of `%SystemRoot%\WinSxS`; needs no
    scan) — runs Windows' own `dism.exe /Online /Cleanup-Image /StartComponentCleanup [/ResetBase] /English`
    (`Security/ComponentCleanup.cs`): the step Windows' scheduled servicing task runs, without its 30-day wait. It
    removes superseded component versions; with `/ResetBase` (its own button, never the default) installed updates
    can no longer be uninstalled. Once started it is not interrupted.
  - *Superseded app versions* (button in the action row; needs no scan) — older versions of app packages in
    `Program Files\WindowsApps`, which DISM does not touch. Removes the unused ones you leave ticked through Windows'
    own `Remove-AppxPackage` (`Security/AppVersions.cs`): versions staged for the system only **as SYSTEM, through a
    one-off scheduled task** `AclLegibility-<id>` that it registers, runs and unregisters again; versions registered
    only for deleted accounts with `-AllUsers`. Deletes the folders Windows no longer knows that you tick (none by
    default), with backup semantics like the leftover folders above. Afterwards it asks Windows again and checks the
    disk: only that check counts as removed or freed.
  - *Clean up orphaned SIDs* (above) also deletes leftover folders and profiles of deleted accounts.

  The three permission actions write a verified backup of the entries they change to a place you choose before
  changing anything. Deleted files, folders, profiles, removed app versions and removed download marks cannot be
  restored by the app. While any of the six actions runs, the window does not close, and Windows holds a shutdown or sign-out with the reason on its
  "apps are preventing shutdown" screen (`user32.dll › ShutdownBlockReasonCreate`; it can still be forced there).
- **Asks once before the six actions are available** (*ἈΝΑΓΝΩΣΙΣ*, see *Consent* below). Until you agree the app is
  read-only; the agreement is one registry value, `HKCU\Software\GeekAclTool › ConsentVersion` (DWORD,
  `advapi32.dll › RegSetValueExW` via .NET's `Registry`). Nothing else is written to the registry.
- **Reads or sends personal data:** reads the names of files, folders and accounts across the whole machine:
  `netapi32.dll › NetUserEnum`, `NetLocalGroupEnum`, `NetLocalGroupGetMembers` (`Scanning/SystemInventory.cs`) and
  `advapi32.dll › LookupAccountSidW` (`Native/SidResolver.cs`). For the details panel and the Risks tab it also
  reads, on demand and read-only:
  - file time stamps (`kernel32.dll › GetFileInformationByHandleEx`, FileBasicInfo);
  - file contents, through `kernel32.dll › CreateFileW` with backup semantics and `ReadFile` (`Native/FileProbe.cs`,
    `LiveReads`): scheduled-task definition files under `System32\Tasks` (up to 512 KB, as XML, `System.Xml`, no
    DTDs), Group Policy records (`.pol`, up to 1 MB, only the key and value names are shown), the first 4 KB of
    files the knowledge base explains by their text (such as `desktop.ini`), and an alternate data stream's first
    16 KB when you press *Show contents*;
  - the services list (`HKLM\SYSTEM\CurrentControlSet\Services`: Type, ImagePath, ObjectName, ServiceDll) and the
    install history (`HKLM\SYSTEM\Setup\Source OS …`, `CurrentVersion\InstallDate`);
  - before a changing action, DISM's record of mounted images (`HKLM\SOFTWARE\Microsoft\WIMMount\Mounted Images`:
    Mount Path, Image Path, Image Index; `Security/ForeignWindows.cs`);
  - for *Superseded app versions*, Windows' package list with the accounts each package is registered for and the
    packages it depends on (`Get-AppxPackage -AllUsers`, `Get-AppxProvisionedPackage -Online`, read only);
  - during a scan, the account SIDs Windows records outside its account database: User Manager's records
    (`HKLM\SOFTWARE\Microsoft\UserManager\Users`, value `Sid`) and the app store's per-account keys
    (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore`, key names). Read only, not kept in
    snapshots (`Scanning/SystemInventory.cs`).

  These live in `Security/KnownFacts.cs`, `Security/RiskViews.cs`, `Views/DetailsBuilder.cs` and
  `Scanning/SystemInventory.cs`. Nothing is sent: *Copy for AI* goes to the clipboard (names masked by default);
  saved snapshots contain real, unmasked names.
- **Talks to other computers:** the code opens no connection itself. On a domain-joined machine, Windows answers
  `advapi32.dll › LookupAccountSidW` for domain accounts by asking a domain controller — invisible in the C# code, so
  stated here. On a machine without a domain nothing goes over the network.
- **Starts on its own:** only once, and only while you watch. *Superseded app versions* registers a one-off task
  `AclLegibility-<id>` that runs `powershell.exe` as SYSTEM for staged versions (`Register-ScheduledTask` in
  `Security/AppVersions.cs`), waits for it and unregisters it right after, also when something fails. Nothing starts
  at boot, at sign-in or on a schedule, and nothing stays registered.
- **Starts other programs:** "Open app folder" starts `explorer.exe` (`Process.Start`, `MainWindow.xaml.cs`); the
  component store clean-up starts `%SystemRoot%\System32\dism.exe` with the arguments above (`Process.Start`,
  output read back and shown); *Superseded app versions* starts Windows PowerShell 5.1
  (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -EncodedCommand …`): once for the read-only query, once per version removed with `-AllUsers`, once per 5 staged
  versions and once for the check afterwards. For staged versions that PowerShell uses Task Scheduler's cmdlets to
  register a one-off task `AclLegibility-<random id>` running the same `powershell.exe` as **SYSTEM**, start it, wait
  for it and unregister it (also when anything fails; leftover `AclLegibility-*` tasks of an interrupted run are
  removed first). The task writes its result to `%SystemRoot%\Temp\AclLegibility-<id>.txt`, which is read and
  deleted. The scripts are in `Security/AppVersions.cs` (`QueryScript`, `RemoveScript`, `SystemRemoveScript`).
  Nothing else.

## What it doesn't do

- **No clean-up of Hyper-V's leftover entries.** It names and explains the entries Hyper-V leaves on files a VM
  used, including those of deleted VMs; removing them is up to the tool that manages the VMs, or to you.
- **No changes by reading.** Scanning, classifying, exporting and snapshots change nothing on the system. Only the
  six actions above write or delete, and only after a preview or confirmation.
- **No permission changes inside `%SystemRoot%`.** No action changes an owner or an entry under the Windows folder;
  the clean-up and the undo of Explorer grants list what they find there. Two things do delete there: single files
  that a knowledge entry marked *removable* explains as leftovers of a deleted account (WDI StartupInfo files,
  `appcompat\Backup` records, `System32\LogFiles\setupcln` logs), offered one by one, never ticked by default; and
  the component store clean-up, which is Windows' own tool removing Windows' own superseded versions.
- **No assumptions about another Windows.** A folder holding `Windows\System32` other than the running Windows (a
  second drive, `Windows.old`, a mount folder) or an image DISM records as mounted may be a separate installation or
  image. When an action would change something in such a place, it asks — *Separate — leave it alone* or *Not
  separate — include it*, Enter means Cancel — and a place you call separate is left alone completely and shown in
  the preview. When there is no such place, nothing is asked.
- **No judgement on what is missing.** Stock items and links a standard install creates but this scan does not
  contain are listed apart (*Not present in this scan*, Knowledge base tab), never as findings: images built with
  fewer components and deliberate clean-ups leave them out on purpose.
- **No verdict on safety.** Stock, Custom and Modified say where something comes from, not whether it is dangerous.
  A Custom entry can be exactly right; a stock one can be wrong for your purpose. The Risks tab shows where a
  privilege escalation *could* start (write access for non-admins, replaceable programs that run as SYSTEM); it does
  not say anyone used it. Deciding is yours.
- **No guessing at history.** Windows does not record who wrote an ACL, which build or program did it, or why. The
  app shows what is on disk (time stamps, descriptor flags, task registration data, dates inside GUIDs, the
  install and upgrade history) under *Known*, and says plainly what is *Not recorded*.
- **No following of links.** Junctions and symbolic links are recorded with their targets, never walked into.
- **No certainty beyond its tested ground.** The knowledge base (version 14) is written for Windows 10, Windows 11,
  Server 2019 and Server 2025. Windows 11 26H2 (build 26300) is calibrated against a clean install: its scan shows
  0 objects needing attention, and those entries are *observed*. Defender's version folders and the Hyper-V store
  are known by rule only (*assumed*): no clean install with those ACLs exported or the feature turned on has been
  compared yet. The rest is *assumed* or *documented* until a clean install of that version confirms it. Other
  Windows versions are scanned but marked "untested OS".
- **No changes to the registry or services, and no lasting scheduled task** — apart from the one consent value
  `HKCU\Software\GeekAclTool › ConsentVersion` (see *Consent*). The only task it creates is the
  one-off `AclLegibility-<id>` for removing staged app versions, unregistered again right after. It examines file system objects, shares, local
  accounts and groups. The registry is read for facts about the machine: the Windows version and install date
  (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`), the upgrade history (`HKLM\SYSTEM\Setup\Source OS …`),
  where profiles live and which account each profile folder belongs to (`…\ProfileList`), DISM's mounted images
  (`…\WIMMount\Mounted Images`), and — for the Risks tab — which services run as what. App packages are only
  removed through Windows' own `Remove-AppxPackage`, never by deleting a folder Windows still lists. Services and
  tasks are only read; commands that remove a task are shown to copy. Settings it explains (e.g. switching off Windows Error Reporting) are shown to copy, never changed.
- **No network, telemetry or update checks.** See "Talks to other computers" for the one thing Windows may do on
  its behalf.
- **No memory between runs** apart from `AclLegibility.json` (settings), the consent value in the registry and files
  you save yourself.

## Build and files

- `dotnet publish -c Release` with the .NET 10 SDK produces one self-contained `AclLegibility.exe` (win-x64, native
  libraries included). No third-party packages; no debug symbols; the version carries no commit hash.
- **The SDK is pinned to .NET 10 LTS** by `global.json` (`10.0.100`, roll forward to the latest 10.0 feature band).
  Without it, `dotnet` takes the newest SDK installed — since November 2026 that is .NET 11, a short-term release,
  which builds different bytes and can fail on older setups. With the pin, a machine without a .NET 10 SDK stops
  with a clear message instead. On GitHub Actions, `actions/setup-dotnet` with `global-json-file: global.json`
  installs the matching SDK.
- While it runs, the app turns on backup and security privileges for itself only, so it can read every security
  descriptor including auditing (SACL). The three permission actions additionally turn on the restore privilege
  for themselves; *Clean up orphaned SIDs* and *Undo Explorer grants* also take-ownership, as does deleting the
  app-package folders Windows no longer knows.
- Files next to the exe: `AclLegibility.json` (settings, created on first run) and, if you create it,
  `knowledge.user.json`. The app itself writes nothing to AppData or the user profile; the registry gets only the
  consent value. Backups and the ZIP of personal files go wherever you choose in the save dialog.
- **WPF's native libraries are unpacked at start** — .NET's standard mechanism for a single-file WPF app
  (`IncludeNativeLibrariesForSelfExtract`): before any of the app's code runs, the .NET host unpacks
  `wpfgfx_cor3.dll`, `PresentationNative_cor3.dll`, `D3DCompiler_47_cor3.dll`, `PenImc_cor3.dll` and
  `vcruntime140_cor3.dll` to `%TEMP%\.net\AclLegibility\<id>\` and reuses them on later starts. Windows can load a
  native library only from a file; every single-file WPF app does the same.

## What it shows

### Shared ideas

- **This object vs. below** — the list column *This object* is the object's own state only; a row without a finding
  of its own says *inherits* (or *as parent* when it repeats its parent's explicit entries — in Findings those are
  folded into the parent's finding: "plus N objects below with the same explicit entries", so one decision shows
  once). The tree pills count what is below ("6 modified below"), and the details panel opens with one line keeping
  both apart: "This folder: Stock · Below: 6 modified, 183 unknown".
- **Origins** — see the table below. *Stock, differs* is a known Windows object that differs from the reference
  install only in ways that give no one more control: read or list rights, or which of SYSTEM, Administrators and
  TrustedInstaller holds a right or owns it. Another build or an update usually wrote it, and an in-place upgrade
  keeps existing ACLs. Shown quietly, not counted as needing attention; the differences are listed. Anything that
  gives someone write, delete, ownership or permission-change rights, removes protection or a deny entry stays
  *Stock, modified* (red). A missing deny entry for an account of another machine (such as Microsoft's image-build
  accounts) never applied here and is not reported as a loss of protection. Knowledge entries can also name known
  variants of an ACL, which then count as Stock.
- **Stock, per account** — Windows' layouts that exist once per account (profile folders, Group Policy's per-account
  record, WDI StartupInfo, appcompat backup records, per-account tasks, setup clean-up logs) are their own quiet
  origin when they name an account that exists, so they stand apart from Custom. With a deleted account they are
  leftovers (Trace); inside `%SystemRoot%` the clean-up offers those it can explain.
- **Known / Not recorded** — for every object: when it was created, when its metadata last changed (NTFS updates
  this on an ACL write too, so the current ACL is that old or older), the DACL flags (protected, auto-inherited),
  dates and adapter kinds inside version-1 GUIDs in its name, and for task files the task's own registration data
  (author, date, version, source, URI, who it runs as, what it runs) — a task that runs as a deleted account is
  marked *dead task*. For an object that differs from stock it adds this Windows' install and upgrade history and
  one plain line on what Windows does not record. Also:
  - *Created together with* — other objects created in the same second (from creation times recorded during the
    scan), which ties files to the install or update step that made them.
  - *Policy records* — for `.pol` files (Group Policy's registry records), the policies they hold.
- **What it is** — the knowledge base explains some files and folders by name: `desktop.ini` (Explorer's folder
  customisation, with its contents shown), `defaultuser0` (setup's temporary account), `Default` (template for new
  profiles), Windows Error Reporting's folders (with where to switch reporting off, to copy). A folder in the profiles
  folder shows whose profile it is according to Windows' profile list, or that no account uses it any more.
- **Instructions** — "how to change it" texts are split into *reversible* steps (with the line that restores them) and
  *not reversible* ones. The app never runs them.
- **Hyper-V entries** — Hyper-V gives a VM's own account (`NT VIRTUAL MACHINE\<VM id>`, S-1-5-83-1-…) and its
  worker-process capability (S-1-15-3-1024-2268835264-…-1612460704, which Windows shows as "Account Unknown") explicit
  access to every file a VM uses: read on an attached ISO or disk, full control on the VM's own files. The capability
  is named *Hyper-V VM worker process (capability)*. Files with only these two kinds of explicit entries are **Stock**
  wherever they are. Hyper-V does not remove the entries when a file is detached or a VM deleted: after a scan of
  every drive, a VM account whose VM id has no `<VM id>.vmcx` anywhere (a VM's own configuration, or vmms's cache in
  `%ProgramData%\Microsoft\Windows\Hyper-V\Virtual Machines Cache`) is labelled *(VM gone)*, and a file whose VM
  entries are all of deleted VMs is a **Trace**. A folder scan, or a machine without Hyper-V, marks nothing as gone.
- **Broad Deny entries** — an explicit Deny for Everyone, Authenticated Users, Users, SYSTEM or Administrators is
  drawn in the error colour: the Deny tag in the permission table, the finding's summary, its kind (“· broad Deny”) in
  the Findings and Explorer lists, and a *broad Deny* badge on the folder in the tree. Windows sets such entries only in
  a few places the knowledge base knows (the legacy junctions in profiles); anywhere else the finding counts as
  **Custom**, even when only built-in principals are involved.
- **Inherit-only entries on files** — a file has no children, so an entry marked inherit-only (IO) applies to nothing
  there and Windows ignores it. Such entries appear when a folder's descriptor is written onto a file as it is (some
  unpackers and copy tools do this). Their *Applies to* reads "Nothing — inherit-only on a file, Windows ignores it";
  effective access already leaves them out.
- **Links** — junctions and symbolic links are drawn in indigo in the tree and the content list: full indigo when
  they are not stock, a softer indigo for the compatibility links Windows creates. The knowledge base knows those
  links and where each must point; a known link with a different target is *Stock, modified*, and every other link
  is Custom (Unknown inside areas Windows manages). A known link that is not there is listed under *Not present in
  this scan*, not in the tree. App aliases, cloud placeholders and other reparse points stay plain.
- **Explorer grants** — Windows Explorer's "You don't currently have permission… Continue" dialog does not borrow
  the administrator's access: it permanently adds the signed-in account to the folder with *full control* for the
  folder, its subfolders and files (observed on Windows 11 build 26300: one entry, on the folder clicked only,
  children inherit it). On another account's profile that hands over its startup folder and scripts. Every folder
  carrying exactly that mark for an existing user account (other than in its own profile and its own recycle bin)
  gets an "Explorer grant" finding — always *Stock, modified* (red), with a red pill in Findings and a red notice in
  the header ("n Explorer grants") that opens exactly those. The undo button sits right under each grant's card. The
  finding says what it means: the grant goes to the account, not to Administrators, so every unelevated process of
  that account can open the folder — UAC no longer applies to it — and that an elevated file manager or PowerShell
  avoids the grant altogether. On an account that no longer exists, the same shape is reported with the orphan as
  "probably an old Explorer access" — probably, because Windows does not record who clicked.
- **Leftovers** — a profile folder whose account no longer exists (or that is in no account's profile entry at all)
  is shown quietly as a leftover (Trace) with the command that removes it, not as a modified profile. Task files
  and task folders under `System32\Tasks` that name a proven orphan explain that they are task definitions and give
  the `Unregister-ScheduledTask` line; the clean-up lists them under "found, not touched".
- **Superseded versions** — app package folders named `Name_Version_Arch_Resource_PublisherId` with a newer version
  of the same package beside them are listed quietly with their size and the command that shows whether Windows
  still uses them; *Superseded app versions…* in the action row asks Windows and removes the unused ones. Windows'
  own record of a version in `ProgramData\Microsoft\Windows\AppRepository\Packages` goes with the package, so a
  record whose folder is in WindowsApps is named in that finding and not counted again; a record without such a
  folder stays a finding of its own. The header
  shows "WinSxS: n superseded components" when the component store holds older versions; it opens WinSxS, whose
  details start with the clean-up.
- **Task accounts** — scheduled-task SIDs (S-1-5-87-…) are named "NT TASK\<task>" when deriving the SID from a task
  name in the store gives exactly that SID; otherwise they stay unnamed. Never guessed.
- **Lists never cut text off** — columns size to their content and the list scrolls sideways when the panel is narrow.

### Explorer tab

Folder tree with **+** (expand the selected branch, up to 5,000 rows) and **−** (collapse to the drives). Badges
count the *objects* below that need attention: a red pill "x modified" only when something below is modified, and a
second pill for the rest, coloured by the worst origin among them (the tooltip says "x of y modified" and breaks it
down). "Only branches with findings" hides everything that is purely stock or traces — except links, which always
stay visible. For a folder, *Who's below* lists the top owners of everything below it and the accounts named in
explicit entries below it, each with an object count — "who made these 6,000 files?" in one look.

### Findings tab

Everything notable: permission breakpoints (explicit entries, inheritance disabled, auditing, integrity labels),
orphaned SIDs, links, alternate data streams, reparse points, hard links, case-sensitive folders, EFS, compression,
sparse files, object IDs, long paths, unreadable objects, superseded package versions. Filter pills by origin, kind
and — for unreadable objects — cause (in use, denied, gone during scan, path or name, cloud / offline, device or
I/O, not supported), each with its count. The "Link" pill shows all links, stock ones included. The pre-selected
origins filter as usual; a pill switched on while nothing it stands for lies inside the current selection clears
the other rows, so clicking *Unreadable 4* shows those 4 even when none of them is Custom or Unknown.

### Risks tab

- *Writable by non-admins*: explicit entries under `%SystemRoot%`, the Program Files folders, ProgramData and on the
  system drive root that let someone other than SYSTEM, TrustedInstaller or Administrators write, create, delete,
  change permissions or take ownership. Each is marked *exact entry* (a knowledge entry compared the whole ACL),
  *rule only* (a rule knows the accounts there, not the rights) or *unexplained* (first, red), with how many objects
  below inherit it. The clean reference install shows 65 writable places, none unexplained.
- *Runs as SYSTEM, not from Windows*: services and scheduled tasks running as SYSTEM, LOCAL SERVICE or NETWORK
  SERVICE with a program outside the Windows folder (tasks: also outside `\Microsoft\`), and any whose program or its
  folder a non-admin can change — that combination is red and first.
- Tasks that run as a deleted account, with the commands that remove them.

### Accounts & groups tab

Every principal seen anywhere, local users and groups with memberships, where each one has explicit entries, how
many objects it owns, and through which groups. A switch shows only orphaned or unverifiable SIDs.

- **Lingering traces of deleted accounts** — a deleted account that Windows still remembers in User Manager's records
  or the app store's per-account keys is listed as an orphaned SID *(lingering trace)*, Trace, with where it lingers.
  It occurs in no security descriptor, so it grants nothing; Windows offers no supported removal, and the app leaves
  it alone. Typical after an automated install that creates and deletes a setup account.
- **Orphaned SIDs** — *proven* when Windows confirms no account has the SID (or it is from this machine's own
  account database, or the machine has no domain); *unverifiable* when the lookup failed for another reason, e.g.
  an unreachable domain controller. Reported where they start, not on every object below. An orphaned SID that only
  appears as the primary group of objects (no entries, owns nothing) is marked *primary group only* and counts as
  Trace: Windows ignores the primary group for access.
- **Capability SIDs** (S-1-15-3-1024-…) are named where they match a known capability name (Windows derives them
  from the name, so the app derives the known ones and compares).

### Shares tab

Share permissions plus a link to the folder's NTFS view.

### Knowledge base tab

What is loaded, what the origins mean, and a kind × origin table of this scan. Below it, *Not present in this
scan*: the stock items and compatibility links a standard install of this Windows creates that the scan does not
contain, grouped by folder, each with its knowledge entry on demand. Only volumes scanned from their root are
checked, nothing is listed after a cancelled scan, and below a folder that could not be listed nothing is said to
be absent (the folder is named instead).

### Changes tab

*Compare Snapshot* compares the current scan with an earlier snapshot (the baseline) and lists only what
changed: new findings that need attention, security changed on existing objects (owner, inheritance, explicit
entries added or removed), objects added (by folder and by owner) and removed (by folder). Only drives present in
both are compared. Take a baseline after a clean-up, compare after a patch day.

### Origins

| Origin | Meaning | Counts as needing attention |
| --- | --- | --- |
| Stock, modified | A known Windows object that differs from the knowledge base in a way that gives someone more control (a redirected stock link included) | yes |
| Custom | Configuration made after setup — by you, your apps or installers: non-Windows accounts, app pool identities, proven orphaned SIDs, explicit entries outside the areas Windows manages | yes |
| Unknown | Not decidable yet — a gap in the knowledge base | yes |
| Stock, differs | A known Windows object that differs from the reference install only in read/list rights or in which system account holds a right or owns it | no |
| Trace | A leftover of normal use: download marks, object IDs, hard links outside Windows, sync metadata | no |
| Stock, per account | Windows' own per-account layout naming an account that exists: a profile, a Group Policy record, a task or a log of that account | no |
| Stock | Shipped or set by Windows setup or servicing | no |

What is not present at all has no origin: it is listed apart (see *Knowledge base tab*).

## Reset to inherit

For a folder (or a whole drive) on a drive other than the running Windows' drive, *Reset to inherit…* in the
details panel removes the explicit entries of everything below and lets it inherit. It works on a live, complete
scan only. If something below holds another Windows (see *What it doesn't do*), you are asked first; a place you
call separate is left alone with everything in it.

1. **Preview** — how many objects change, which already inherit, which are left as they are and why, and what
   everything will inherit.
2. **Left as they are** — `$RECYCLE.BIN`, `System Volume Information`, links, and every object whose explicit entries
   serve a virtual machine, a service, an IIS app pool or an app package (found by their SIDs, not by folder names).
   Owners, auditing entries and integrity labels are never touched.
3. **Backup** — a save dialog asks where to put the backup (it suggests Documents, not the app folder, which may be
   on a USB stick). Cancelling changes nothing. The file is written in icacls format and read back before the first
   change; if that fails, nothing is changed.
4. **Change** — parents before children, so each object inherits from its final parent.
5. **Result** — the folder is read again in place, and one message names the backup file and the exact restore
   command, e.g. `icacls D:\ /restore "<file>" /c`, to run in an elevated PowerShell.

**A drive root in a backup** (*Clean up orphaned SIDs* and *Undo Explorer grants* can change one): `icacls /save`
writes an empty name line for the folder it starts from, but `icacls /restore` cannot read that line back — it takes
the SDDL for the name and every entry after it fails (tested on Windows 11 26H2). So the root's entries go into a
second file next to the backup, `<backup>-root.txt`, as one PowerShell line (`Get-Acl`, `SetSecurityDescriptorSddlForm`,
`Set-Acl`), and the restore message prints it after the icacls line. The entries come back as saved; .NET writes them
in canonical order and marks the list auto-inherited (`AI`), so the root's restore is equivalent, not byte-identical.

## Clean up orphaned SIDs

Deleting a user (e.g. clearing out a profile) leaves its SID behind as owner of everything it created, in any
entries made for it, and as the name of folders Windows made for it. In *Accounts & groups*, a proven orphaned SID
offers *Clean up this SID…*; *Clean up all proven orphans…* does every one at once.

- **Owners** that are a proven orphan become **Administrators**.
- **Explicit entries** for those SIDs are removed; every other entry and the protection flag stay. If a protected
  object had only the orphan's entries, inheritance is turned on instead of leaving it with no entries at all.
  This includes areas Windows manages (Program Files, ProgramData, profiles, …).
- **Profiles** of those accounts that Windows' profile list still names are part of the clean-out: **deleted**
  completely (folder and list entry) through `DeleteProfileW` — the same as "Account Unknown → Delete" in System
  Properties. The preview shows each with its size and its personal files outside AppData by type (documents,
  pictures, videos, audio, archives, keys/certificates/password databases). If any profile has some, the main button
  becomes *Back up personal files as ZIP, then clean up…*: you choose where, the ZIP is written and checked (names
  keep their case, so `Notes.txt` and `notes.txt` from a case-sensitive folder are both kept), and nothing is deleted
  unless that worked; *Clean up without saving personal files* stays possible. Files of those types inside AppData
  are listed separately and do not trigger the offer (they are app data: logs, icons, caches). A loaded profile is
  refused by Windows and listed. Cannot be undone.
- **Leftover folders** named after the SID — a deleted account's Group Policy data
  (`ProgramData\Microsoft\GroupPolicy\Users\<SID>`), its recycle bin on every drive (`$Recycle.Bin\<SID>`) and the
  like — are **deleted** with everything in them. The preview shows each one with its size. This cannot be undone.
- **Inside `%SystemRoot%` it only looks** — unless it is explained. Windows, WinSxS and System32 are servicing
  territory: whatever is found there (owners, entries, SID-named folders) is listed as "found, not touched" and
  stays exactly as it is. Files a knowledge entry marks as removable *and* explains get their own section, "Inside
  Windows, explained, safe to remove", with the explanation and a tick box each, none ticked by default. Only
  ticked files are deleted. In knowledge base v14 those are, for deleted accounts: the WDI StartupInfo files
  (`System32\WDI\LogFiles\StartupInfo\<SID>_StartupInfo*.xml`, which the Diagnostic Policy Service never removes),
  the per-account records under `appcompat\Backup`, and the logs of Setup's clean-up under
  `System32\LogFiles\setupcln` that grant the deleted account.
- **Left as they are:** links, drive roots, auditing entries, integrity labels, every unverifiable SID — and SIDs the
  knowledge base knows, such as the Administrator and Guest of the machine Microsoft builds the installation image on
  (`S-1-5-21-4024195226-107334468-2656468696-500/-501`): they are baked into Windows media, sit on a few scheduled
  tasks and `ProgramData\Microsoft\DeviceSync` on every installation, and are part of Windows as shipped.
- **Another Windows:** if anything planned lies in a place that may hold another Windows installation or image, you
  are asked first (see *What it doesn't do*); a place you call separate is left alone and named in the preview.
- **Preview first**, then — when entries change — a save dialog for the backup (icacls format, one file per drive),
  verified before the first change. Owners are not backed up (the old account no longer exists) and deleted folders
  cannot be restored. Afterwards the changed objects are read again and one message names the backup files and
  restore commands.
- Deleting uses the restore privilege with backup semantics, so a folder that grants access only to the deleted
  account can still be removed; read-only and system attributes are ignored. Anything that cannot be deleted (in use,
  created after the scan) is listed and its folder stays.

## Undo Explorer grants

From an "Explorer grant" finding (*Undo …'s grant here…*) or in *Accounts & groups* per account (*Undo this
account's Explorer grants…*):

- **Preview** lists every folder with the mark, each with a tick box: untick the ones you granted on purpose — a
  deliberate grant set by hand looks exactly the same.
- **Removes only that one entry**: the account's full-control (OI)(CI) entry. Every other entry, the owner and the
  protection flag stay; subfolders and files lose the inherited copy with it.
- **Inside `%SystemRoot%` it only looks**, and a place you call another Windows is left alone.
- **Backup** of the entries that change (icacls format, one file per drive, verified before the first change) and
  the restore command afterwards.

## Remove download marks

*Remove download marks…* in the details panel of a folder or drive (live scan) works by location, not by age.

1. **Read** — every file below whose scan shows a `Zone.Identifier` stream; the mark itself is read from the disk now.
   Progress shows *n of total* and the current path; Cancel stops reading.
2. **Preview, grouped by what the mark says:**
   - Data files: *Bare mark* (`ZoneId=3`, no source) — ticked; *Downloaded from <host>* (`HostUrl`, else
     `ReferrerUrl`) — ticked, one group per host; *other zones* (e.g. 4, restricted) and marks that cannot be read —
     not ticked.
   - **Programs and scripts** (`.exe`, `.dll`, `.msi`, `.cmd`, `.ps1`, shortcuts, disk images, macro-capable Office
     files, …) — one card of their own with one tick, not set by default, split inside by the same kinds of mark: for
     those the mark is what makes SmartScreen or Smart App Control check them.
   - Bare marks come from Windows' own zip handling, which copies an archive's mark onto the risky types inside only;
     data files from the same archive stay unmarked. So bare marks usually sit on programs only, and the defaults then
     remove nothing — the preview says so.
3. **Run** — only the stream is deleted (what the *Unblock* box in a file's Properties does), also on read-only files
   (`FileDispositionInfoEx` with *ignore read-only*; the attribute stays); the file's time stamps are put back; then the
   folder is read again. The result in the details panel lists every file that kept its mark, by Windows' reason. No
   backup: a mark comes back only with a new download.

The preview also explains where bare marks come from and names the policy *Do not preserve zone information in file
attachments* that stops new marks — as text; the app does not change it.

### What the mark does and doesn't do

The same facts appear in the preview and under a file's `Zone.Identifier` stream in its details, side by side and
without a verdict — the decision is yours:

- **Does:** Windows blocks a file that carries the mark. SmartScreen and Smart App Control check a program before it
  runs; Office opens a document read-only in Protected View, without macros, data connections or Power Query;
  *Unblock* in the file's Properties removes the mark.
- **Fails:** lost on copy to a disk that is not NTFS (FAT32, exFAT, many shares and sync tools) and usually when a
  third-party tool unpacks an archive. Writing it is voluntary: browsers and mail clients do; curl, git, package
  managers and the self-updaters of conferencing and remote-support tools usually do not; signed code passes
  SmartScreen on reputation anyway. It matters at the first double-click after a browser or mail download; on files
  that have been on disk for months it is noise rather than protection.
- **Baselines:** formal baselines take the opposite view: the DISA STIG and the CIS Benchmark both require the mark to
  be kept, and enabling *Do not preserve zone information in file attachments* is a medium (CAT II) STIG finding —
  though CIS's own text concedes the mark works only on NTFS and is lost without notice on FAT32.

## Component store clean-up

*Component store clean-up…* at the right end of the action row runs Windows' own
`dism.exe /Online /Cleanup-Image /StartComponentCleanup /English` on the running Windows, with or without
`/ResetBase` — two separate buttons in the confirmation; Enter means Cancel. It is the only way to start it: the
details of `%SystemRoot%\WinSxS` explain the store and have a *Show the clean-up button* that makes this button pulse
and gives it focus. It needs no scan: on a system
that has not been cleaned up, superseded versions can be a large part of everything a full scan reads, so run it
first. DISM is never interrupted; with a live scan loaded WinSxS is read again afterwards.

## Superseded app versions

*Superseded app versions…* next to it handles what DISM does not: older versions of app packages in
`Program Files\WindowsApps` with a newer version of the same package beside them. Needs no scan.

1. **Ask Windows** (read only): `Get-AppxPackage -AllUsers` lists every package with the accounts it is registered
   for and the packages it depends on; `Get-AppxProvisionedPackage -Online` lists what new accounts get.
2. **Preview**, one group each:
   - *Still used* — left alone, with the reason: registered for an existing account, another app depends on it,
     provisioned for new accounts, or marked non-removable by Windows.
   - *Staged for the system only* — Windows keeps it ready for the system (`S-1-5-18 … Staged`), installed for no
     account, and no app depends on it. Ticked; untick to keep.
   - *Registered only for deleted accounts* — no existing account uses it and no app depends on it. Ticked.
   - *Not known to Windows* — Windows lists no package by that name: a leftover folder. None ticked.
3. **Run** — staged versions are removed **as SYSTEM**: `Remove-AppxPackage` from an administrator, even with
   `-AllUsers`, answers OK and leaves a staged version in place; run as SYSTEM it removes it (folder and record
   included — tested on 26H2). The app registers a one-off task `AclLegibility-<id>` that runs as SYSTEM, removes up
   to 5 versions, and is unregistered right after. Versions registered only for deleted accounts get
   `Remove-AppxPackage -Package <full name> -AllUsers`. Then the ticked leftover folders are deleted with backup
   semantics (anything in use is listed and stays). Cancel stops between steps. No backup: a removed version comes
   back only by installing it again.
4. **Check** — Windows is asked again and the disk is looked at. Each version is reported as removed and gone,
   removed but its folder still on disk, or not removed (Windows still lists it); only what is gone counts as freed.
   The removal's own "OK" is never taken as proof. The result panel lists every version with its route (as SYSTEM,
   with `-AllUsers`, folder deleted by the app), Windows' answer in plain words — e.g. 0x80073D02 becomes "in use by
   a running app — close it or restart Windows, then run this again" — and Windows' full text on demand.

The preview also lists packages Windows still reports as installed for **accounts that no longer exist**. They are
left as they are: `Remove-AppxPackage -User` refuses an account Windows cannot resolve, `-AllUsers` would also remove
the package from accounts that use it, and Windows offers no other supported removal. They go with a reinstall.

## Knowledge base calibration

The knowledge base (version 14) is checked against snapshots of clean installs (a VM, unattended setup, scanned
before anything else ran). Version 13 added Hyper-V's VM worker-process capability and the rule for files a VM uses
(see *Hyper-V entries*). For Windows 11 26H2 Pro, build 26300, the reference went from 3,082 objects needing
attention to 0. Version 14 added Windows 10 22H2 Pro, build 19045, whose reference went from 109 to 0: 98 of the
Windows 11 entries hold there exactly, nine got a Windows 10 variant (the print spooler without its later
restricted-service SID, rights split into two entries where Windows 11 has one), eight places exist only on
Windows 10 (the fax folders, mixed-reality device data, two scheduled tasks, the Remote Desktop configuration
service's machine key, an Update Orchestrator registration), and the Windows 10 image-build accounts are known by
name. In detail:

- **Patterns** for whole areas with one layout: the WindowsApps store, Edge/WebView2, the AppX repository, Defender
  for Endpoint, per-account layouts inside profiles, the certificate store, per-account scheduled tasks and
  `SystemData`, the shared Start Menu. Pattern principals may use tokens resolved per object: `$OWNER`, `$PROFILE`
  (the profile's account from Windows' profile list), `$ANYPROFILE`, `$NAMESID` (an account SID in the path),
  `$FILENAME` (the account named like the file, e.g. `User Account Pictures\<name>.dat`), `$ORPHAN` and
  `$LOCALADMIN` (this machine's built-in Administrator, whose SID differs on every install).
- **139 exact ACLs** generated from the Windows 11 reference and **8** from the Windows 10 one, for single objects
  Windows sets up individually.
- **Traces**, not configuration: compressed AppX descriptions, servicing and setup logs, shader caches, OneDrive and
  Error Reporting logs.
- **Variants** (since version 10): a path entry may list other ACLs Windows is known to write there, with a label
  saying where they were seen; differences that give no one more control are *Stock, differs* rather than modified.
- **Rule only, not yet compared** (since version 11): Defender's version folders and the Hyper-V store. Their entries are
  *assumed* until a reference with those ACLs exported (and Hyper-V turned on) confirms them.

## Copy for AI

Every object, folder subtree, filtered findings list, principal and the share list can be copied to the clipboard
as Markdown, whatever the size (the status bar shows it; files only via *Save … as Markdown*): OS build, full ACLs
with inheritance sources, SDDL, streams, reparse data, classification and knowledge entry, followed by the
knowledge-entry format so an AI can answer with entries to paste into `knowledge.user.json`.

Masking (on by default) replaces computer, domain and account names with placeholders and hides the
machine-specific part of account SIDs and the network address inside version-1 GUIDs (their date and adapter kind
stay). Profile folder names from Windows' profile list are masked too, as whole path segments, with their account's
placeholder — a deleted account's folder, a renamed account's old folder name and a Microsoft account's shortened
name never go through an account lookup. Account names shorter than 3 characters are masked only as whole path
segments or after a backslash (`PC\jo`), not as words in running text. Windows authorities such as `NT TASK`, `NT SERVICE` and `NT AUTHORITY` are never masked. Accounts in
`AclLegibility.json` → `unmaskedAccounts` (empty by default; add your own accounts there) appear by name only, with their group
memberships.

## Consent

The six actions change the machine; everything else only reads. So the first launch shows **ἈΝΑΓΝΩΣΙΣ**
(*anagnōsis*, Greek: reading; motto γνῶθι πρὶν πράττειν, *know before you act*) with two ticks — the second set
apart, so they cannot be ticked in one sweep — and two buttons:

- **Agree** (both ticked) — stored as `HKCU\Software\GeekAclTool › ConsentVersion`; the app behaves as it always did
  and the screen does not come back.
- **Read only for now** — scanning, the tabs, snapshots and Copy for AI work as usual. A *read only* pill sits under
  the version. Clicking any of the six actions, or the pill, shows the screen again; *Agree* there goes straight on
  to that action's preview.

Clicking the **logo** shows the text again; after agreeing, as *the terms you accepted*, with both ticks locked and
nothing recorded. The stored version is raised only when the text changes materially, which asks once more. If the
value cannot be written, the session goes on and the screen comes back next launch. To start over, delete
`HKCU\Software\GeekAclTool`.

## Settings (`AclLegibility.json`)

| Key | Default | Meaning |
| --- | --- | --- |
| `maskByDefault` | `true` | Masking switch at start |
| `unmaskedAccounts` | `[]` | Shown by name in exports |
| `exportMaxItems` | `2000` | Items per export; the rest is summarised by count |
| `animateOverride` | `true` | Busy rings: `true` always turn (override system setting), `null` follow Windows, `false` never |

A `settings.json` from 0.1.0/0.1.1 is taken over once and removed.

## Snapshots

**Save snapshot** writes a compressed `.aclsnap` with raw descriptors, names, OS facts and folder layout — enough to
re-classify later or on another machine (e.g. a clean VM scan as a reference). Snapshots contain real, unmasked
names.

- **Format 8** (since 0.2.4). Older formats open; what they did not record is simply absent. A snapshot in a newer
  format than the app knows is refused with a message saying so.
- Format history: 6 (0.1.12) added the install and upgrade history; 7 (0.1.13) added each object's creation time
  (read from the directory listing, no extra cost); 8 (0.2.4) marks snapshots whose folder streams can be trusted.
- Versions up to 0.1.6 recorded hard-link counts wrongly (part of the file ID instead of the count); when such a
  snapshot is opened the counts are dropped and the status bar says so.
- Versions up to 0.2.3 could give a folder without streams the streams of the file scanned just before it (the
  stream query's returned length was ignored and a reused buffer read). When a snapshot of format 7 or older is
  opened, streams on folders are dropped and the status bar says how many; streams on files are kept. Real folder
  streams are rare, so a rescan is the way to see them.

## Theme

HueTheme kit 1.1.5, Platinum family (oversight and authority), neutral surfaces, glow 0.35. The kit files
(`Theme/HueTheme.xaml`, `Theme/HueThemeKit.cs`, `BusyOverlay/*`) are unchanged and keep their stamps.

### Deviations from HueTheme

AclLegibility is a shield-frame instrument; these deviations are deliberate. App-owned additions live in
`Theme/AclLegibility.Extras.xaml`, marked with `APP` markers so they can be fed back into the kit.

| Rule | Deviation | Why |
| --- | --- | --- |
| Categories: neutral tags; accent for one; signal tags only for real risk | Origins use signal tags: Stock, modified → `Hue.Tag.Unsafe`, Custom → `Hue.Tag.Caution`, Unknown → `Hue.Tag`, Stock, Stock per account, Stock differs and Trace → `App.Tag.Quiet` (neutral, muted text) | Origin is the app's verdict axis. The Platinum accent (`#94A3B8`) is too close to neutral to separate Custom from the rest |
| Filter pills: every row starts with none lit | Origin pills start with Stock, modified + Custom + Unknown lit | A full scan has ~1 million findings, mostly stock and traces; the first view should be the work list. Unlit pills still show their counts |
| Never colour alone | Tree badges: a red "x modified" pill (the word is in it) and a second pill coloured by the worst remaining origin; the breakdown is in the tooltip and the details panel | Colour speeds up scanning a deep tree; a single badge coloured by the worst item made a folder with 3 modified among 500 objects look like 500 alarms |
| Categories: neutral tags | Links (junctions, symbolic links) in the kit's Indigo family — `App.Brush.Link` (Indigo.Light), `App.Brush.LinkMuted` (Indigo.Mid, softened) for stock ones; system hyperlink and grey text colours under a contrast theme | Links redirect everything that opens the path; among thousands of findings they must stand out on their own axis, independent of the origin colours |
| Rule 3: no local templates on standard controls | `App.SelectableText` (read-only TextBox without chrome) | Paths, SDDL and SIDs must be selectable and copyable; the kit has no style for it |
| Icons: ask before drawing | `Icon.Drive`, `Icon.Link` drawn on the kit grid | The kit has no drive or link icon |
| Rule 14: no menus | Right-click menus on the result lists | Multi-select "Copy for AI" is the fast path for feeding the knowledge base; every action is also a visible button in the details panel |
| Signal colours only for real risk | An amber rim around *Component store clean-up…*: *Show the clean-up button* in the WinSxS details makes it pulse three times and stay for a few seconds (`Warn.Fill`, set in code) | The button is the only way to start DISM; pointing at it has to be unmistakable, and the kit's Platinum accent is too close to neutral |
| Busy overlay: "Override system setting" checkbox in the settings | `animateOverride` in `AclLegibility.json` only | The app has no settings view; one checkbox does not justify one |

## License

MIT — see `LICENSE.txt`. Copyright (c) 2026 Sascha Eder.

## Source layout

- `Native/` — P/Invoke: backup-semantics handles, security descriptors, streams, reparse data, object IDs, netapi,
  live file reads (`LiveReads`).
- `Scanning/` — parallel walker (junctions/symlinks recorded, not followed), OS detection, local accounts, shares.
- `Model/` — scan tree, findings, security-descriptor table, OS facts, inventory, read-failure causes.
- `Security/` — own security-descriptor parser (all ACE types incl. labels and claims), rights decoding, effective
  access, the write actions, `ComponentCleanup.cs` (DISM), `AppVersions.cs` (superseded app versions),
  `DownloadMarks.cs` (download marks),
  `ForeignWindows.cs` (other Windows installations and mounted images), `KnownFacts.cs` (Known block, task
  definitions, GUID dates, task SIDs, policy records, same-second index) and `RiskViews.cs`.
- `Knowledge/` — `knowledge.json` (embedded), user-file merge, path patterns, classifier.
- `Export/` — Copy-for-AI Markdown and masking.
- `Snapshots/` — `.aclsnap` format and the snapshot comparison.
- `Settings/` — `AclLegibility.json`.
- `Views/` (incl. `ConsentWindow.xaml`), `ViewModels/` (incl. `FindingFilter.cs`, the Findings pill rules), `Theme/`, `BusyOverlay/` — WPF UI on
  the HueTheme kit.
- `Assets/` — `app.ico` (exe/window icon), `app_256.png` (header block), source artwork.
