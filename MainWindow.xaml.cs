using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;
using AclLegibility.Export;
using AclLegibility.Knowledge;
using AclLegibility.Model;
using AclLegibility.Native;
using AclLegibility.Scanning;
using AclLegibility.Security;
using AclLegibility.Settings;
using AclLegibility.Snapshots;
using AclLegibility.Theme;
using AclLegibility.ViewModels;
using AclLegibility.Views;
using BusyOverlayKit;
using HueThemeKit;

namespace AclLegibility;

public partial class MainWindow : Window
{
    private readonly AppSettings _settings;
    private KnowledgeBase _kb;
    private ScanResult? _r;
    private CompiledKb? _ckb;
    private Classifier? _cls;

    private readonly DispatcherTimer _pillTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _scanClock = new();
    private readonly DispatcherTimer _filterDebounce = new() { Interval = TimeSpan.FromMilliseconds(300) };

    private List<TreeItemVm> _treeRoots = new();
    private List<FindingRowVm> _allFindingRows = new();
    private List<PrincipalRowVm> _principals = new();
    private readonly List<ToggleButton> _originChips = new();
    private readonly List<ToggleButton> _categoryChips = new();
    private readonly List<ToggleButton> _causeChips = new();
    private int _filterVersion;
    private readonly string? _startupMessage;

    /// <summary>What is changing the system right now (null: nothing). While set, the window does not close.</summary>
    private string? _running;
    /// <summary>Whether the running action has a Cancel button that stops it at the next safe point.</summary>
    private bool _runningCancelable;

    /// <summary>Origins lit when a result is first shown (deviation: the kit starts with none lit).</summary>
    private static readonly Origin[] DefaultLitOrigins = { Origin.Modified, Origin.Custom, Origin.Unknown };
    private static readonly Origin[] FilterOrigins = { Origin.Modified, Origin.Custom, Origin.Unknown, Origin.Differs, Origin.PerAccount, Origin.Trace, Origin.Stock };

    public MainWindow()
    {
        InitializeComponent();
        HueTitleBar.Attach(this);
        if (Application.Current != null) Application.Current.SessionEnding += OnSessionEnding;

        _settings = AppSettings.Load(out _startupMessage);
        MaskCheck.IsChecked = _settings.MaskByDefault;
        Busy.AnimateOverride = _settings.AnimateOverride;
        _kb = LoadKnowledge();

        VersionText.Text = HueVersion.Text;
        _pillTimer.Tick += (_, _) => ScanPill.Content = "Scan " + Ui.Elapsed(_scanClock.Elapsed);
        _filterDebounce.Tick += (_, _) => { _filterDebounce.Stop(); _ = ApplyFindingFilter(); };
        Tabs.SelectionChanged += (_, e) => { if (ReferenceEquals(e.OriginalSource, Tabs) && RisksTab.IsSelected) BuildRisks(); };

        Loaded += (_, _) =>
        {
            try { ShowOs(SystemInventory.DetectOs(), live: true); } catch { OsTitle.Text = "Windows"; }
            UpdateKbCaption();
            BuildKnowledgePage();
            if (_startupMessage != null) SetStatus(_startupMessage, "Brush.Warn");
            if (!IsElevated()) SetStatus("Not running elevated — many objects will be unreadable. Start AclLegibility as administrator.", "Brush.Warn");
            ShowConsentState();
            if (!_consented)
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ContextIdle, new Action(() => AskConsent()));
        };
    }

    private System.Windows.Threading.DispatcherTimer? _rimTimer;

    /// <summary>From the WinSxS details: an amber rim pulses three times around the action row's clean-up button, stays for a
    /// few seconds, and the button gets focus. The clean-up itself only starts from there, after its question.</summary>
    private void PointToComponentCleanup()
    {
        SxsCleanButton.BringIntoView();
        SxsCleanButton.Focus();
        // Amber on purpose, outside the theme kit: it has to be unmistakable where the button is.
        var amber = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)FindResource("Warn.Fill"));
        SxsCleanRim.BorderBrush = amber;
        amber.BeginAnimation(System.Windows.Media.Brush.OpacityProperty, new System.Windows.Media.Animation.DoubleAnimation(1.0, 0.15, TimeSpan.FromMilliseconds(330))
        {
            AutoReverse = true,
            RepeatBehavior = new System.Windows.Media.Animation.RepeatBehavior(3),
        });
        _rimTimer?.Stop();
        _rimTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(6) };
        _rimTimer.Tick += (_, _) => { _rimTimer!.Stop(); SxsCleanRim.BorderBrush = System.Windows.Media.Brushes.Transparent; };
        _rimTimer.Start();
    }

    // ================================================================================== consent

    /// <summary>Whether the six actions that change the machine are available. Read from HKCU at start; set by agreeing.</summary>
    private bool _consented = ConsentWindow.AlreadyAccepted();

    private void ShowConsentState() => ReadOnlyPill.Visibility = _consented ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Shows the consent screen. True when agreed (the app then behaves as before); false keeps it read-only.</summary>
    private bool AskConsent()
    {
        var agreed = new ConsentWindow { Owner = this }.ShowDialog() == true;
        if (agreed) _consented = true;
        ShowConsentState();
        if (!agreed) SetStatus("Read only: scanning, browsing, snapshots and Copy for AI work as usual. The actions ask again when you click one.");
        return agreed;
    }

    /// <summary>Gate at the start of each of the six actions: passes at once once agreed, otherwise asks.</summary>
    private bool MayAct() => _consented || AskConsent();

    private void Logo_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (_consented) new ConsentWindow(reviewMode: true) { Owner = this }.ShowDialog();
        else AskConsent();
    }

    private void ReadOnlyPill_Click(object sender, System.Windows.Input.MouseButtonEventArgs e) => AskConsent();

    /// <summary>Marks a write action as running: the window does not close, and Windows holds a shutdown or sign-out with
    /// the reason on its "apps are preventing shutdown" screen (where it can still be forced).</summary>
    private void BeginRunning(string what, bool cancelable)
    {
        _running = what;
        _runningCancelable = cancelable;
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            if (hwnd != IntPtr.Zero) NativeMethods.ShutdownBlockReasonCreate(hwnd, $"AclLegibility: {what} is running.");
        }
        catch { /* no reason shown; the session-ending answer below still holds the shutdown */ }
    }

    private void EndRunning()
    {
        _running = null;
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            if (hwnd != IntPtr.Zero) NativeMethods.ShutdownBlockReasonDestroy(hwnd);
        }
        catch { }
    }

    /// <summary>Windows asks before a shutdown or sign-out: while a write action runs, the answer is "not now".</summary>
    private void OnSessionEnding(object? sender, SessionEndingCancelEventArgs e)
    {
        if (_running != null) e.Cancel = true;
    }

    /// <summary>Closing while an action changes the system would stop it half-way (and would cut DISM off from its output),
    /// so the window stays open until it has finished.</summary>
    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_running != null)
        {
            e.Cancel = true;
            HueMessage.Show(this, "Still working",
                _runningCancelable
                    ? $"{_running} is still running. Closing now would stop it half-way.\n\nPress Cancel in the progress view to stop "
                      + "at the next safe point; the window can be closed afterwards."
                    : $"{_running} is still running and is not interrupted once started. The window can be closed when it has finished.");
            return;
        }
        base.OnClosing(e);
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return true; }
    }

    private KnowledgeBase LoadKnowledge()
    {
        try { return KnowledgeBase.Load(null, AppSettings.UserKnowledgePath); }
        catch (Exception ex)
        {
            HueMessage.Show(this, "Knowledge base not loaded", "The built-in knowledge base could not be loaded:\n\n" + ex.Message);
            return KnowledgeBase.Load("{}", null);
        }
    }

    private void SetStatus(string text, string dotBrush = "Brush.Ok")
    {
        StatusText.Text = text;
        StatusDot.SetResourceReference(ForegroundProperty, dotBrush);
    }

    // ================================================================================== header

    private void ShowOs(OsInfo os, bool live)
    {
        OsTitle.Text = (live ? "" : "Snapshot · ") + $"{os.FriendlyName}";
        OsCaption.Text = $"{(string.IsNullOrEmpty(os.DisplayVersion) ? "" : os.DisplayVersion + " · ")}build {os.Build}.{os.Ubr} · {os.InstallationType}"
                         + (live ? "" : $" · {os.ComputerName}");
        TargetPill.Style = (Style)FindResource(os.IsTestedTarget ? "Hue.Pill.Ok" : "Hue.Pill.Warn");
        TargetPill.Content = os.IsTestedTarget ? $"tested target {os.TargetKey}" : $"untested OS · closest {os.FamilyKey}";
        TargetPill.ToolTip = os.IsTestedTarget
            ? "The knowledge base targets this Windows version."
            : "The knowledge base does not target this build yet; stock judgements are provisional.";
    }

    private void UpdateKbCaption()
    {
        KbCaption.Text = $"knowledge base v{_kb.Doc.Version} · {_kb.EntryCount} entries" +
                         (_kb.UserEntryCount > 0 ? $" (+{_kb.UserEntryCount} yours)" : "") +
                         (_kb.LoadMessages.Any(m => m.StartsWith("Could not")) ? " · user file has errors" : "");
    }

    private void StartPill()
    {
        _scanClock.Restart();
        ScanPill.Style = (Style)FindResource("Hue.Pill.Warn");
        ScanPill.Content = "Scan 00:00";
        ScanPill.Visibility = Visibility.Visible;
        _pillTimer.Start();
    }

    private void StopPill(string label, string style)
    {
        _pillTimer.Stop();
        _scanClock.Stop();
        ScanPill.Style = (Style)FindResource(style);
        ScanPill.Content = label;
        ScanPill.Visibility = Visibility.Visible;
    }

    // ================================================================================== scanning

    private async void ScanAll_Click(object sender, RoutedEventArgs e)
    {
        var roots = Scanner.FixedVolumeRoots();
        if (roots.Count == 0) { SetStatus("No fixed volumes found.", "Brush.Warn"); return; }
        await RunScan(roots);
    }

    private async void ScanFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Folder to scan", Multiselect = false };
        if (dlg.ShowDialog(this) != true) return;
        await RunScan(new[] { dlg.FolderName });
    }

    private sealed record Classified(ScanResult R, CompiledKb Kb, Classifier Cls);

    private async Task RunScan(IReadOnlyList<string> roots)
    {
        var kb = _kb;
        using var cancel = new CancellationTokenSource();
        StartPill();
        SetStatus("Scanning…", "Brush.Warn");
        try
        {
            var done = await Busy.RunAsync("Scanning " + string.Join(", ", roots), async report =>
            {
                var progress = new ScanProgress();
                var scan = Task.Run(() => Scanner.Run(roots, progress, cancel.Token));
                while (!scan.IsCompleted)
                {
                    report.Say(progress.Phase == "Scanning"
                        ? $"{Interlocked.Read(ref progress.Objects):N0} objects in {Interlocked.Read(ref progress.Directories):N0} folders · {Interlocked.Read(ref progress.Errors):N0} unreadable · {progress.Current}"
                        : progress.Phase + "…");
                    await Task.WhenAny(scan, Task.Delay(100));
                }
                var r = await scan;
                return Classify(r, kb, report);
            }, cancel);

            Apply(done);
            var res = done.R;
            var attention = res.Findings.Where(f => f.NeedsAttention).Select(f => f.Node).Distinct().Count();
            StopPill((res.Cancelled ? "Cancelled " : "Scan ") + Ui.Elapsed(res.Duration), "Hue.Pill.Stale");
            SetStatus($"{(res.Cancelled ? "Cancelled — partial scan: " : "Scanned ")}{res.ObjectCount:N0} objects in {Ui.Elapsed(res.Duration)}. " +
                      $"{res.Descriptors.Count:N0} distinct security descriptors · {attention:N0} objects need attention · " +
                      $"{res.Findings.Count:N0} findings in all · {res.ErrorCount:N0} unreadable.", res.Cancelled ? "Brush.Warn" : "Brush.Ok");
        }
        catch (Exception ex)
        {
            StopPill("Scan failed", "Hue.Pill.Error");
            SetStatus("Scan failed: " + ex.Message, "Brush.Error");
        }
    }

    /// <summary>Worker half: parse, classify, summarise. Touches no control.</summary>
    private static Classified Classify(ScanResult r, KnowledgeBase kb, BusyReport report)
    {
        var ckb = new CompiledKb(kb, r.Os);
        var cls = new Classifier(r, ckb);
        cls.Run(s => report.Say(s + "…"));
        return new Classified(r, ckb, cls);
    }

    private void Apply(Classified c)
    {
        _r = c.R; _ckb = c.Kb; _cls = c.Cls;
        ShowResult();
    }

    // ================================================================================== result display

    private void ShowResult()
    {
        if (_r == null || _ckb == null || _cls == null) return;
        ShowOs(_r.Os, _r.IsLive);
        UpdateKbCaption();

        // explorer
        _treeRoots = _r.Roots.Select(n => new TreeItemVm(n, null, () => OnlyAttentionCheck.IsChecked == true)).ToList();
        Tree.ItemsSource = _treeRoots;
        ContentGrid.ItemsSource = null;
        ExplorerDetails.Content = null;
        if (_treeRoots.Count > 0) { _treeRoots[0].IsExpanded = true; _treeRoots[0].IsSelected = true; }

        // findings
        _allFindingRows = _r.Findings.Select(f => new FindingRowVm(f)).ToList();
        BuildFilterChips();
        UpdateGrantNotice();
        UpdateSxsNotice();
        FindingDetails.Content = null;
        _ = ApplyFindingFilter();

        // principals
        BuildPrincipals();
        ApplyPrincipalFilter();
        PrincipalDetails.Content = null;
        CleanAllButton.IsEnabled = _r.IsLive && _principals.Any(p => p.Orphan == OrphanState.Proven);

        // shares
        ShareGrid.ItemsSource = _r.Inventory.Shares.Select(s =>
        {
            var (o, e, k, c) = _cls.ClassifyShare(s);
            return new ShareRowVm { Share = s, Origin = o, Explain = e, KbId = k, Confidence = c };
        }).ToList();
        ShareDetails.Content = null;

        BuildKnowledgePage();
        _risksFor = null;
        RisksInfo.Content = null;
        if (RisksTab.IsSelected) BuildRisks();
        SaveSnapButton.IsEnabled = true;
        CompareSnapButton.IsEnabled = true;
    }

    private ScanResult? _risksFor;

    /// <summary>Builds the Risks tab for the current result (once per result): reads services and task definitions live.</summary>
    private void BuildRisks()
    {
        if (_r == null || _cls == null)
        {
            RisksInfo.Content = new TextBlock { Text = "Scan first: the risk views are built from a scan.", Style = (Style)FindResource("Text.Body") };
            return;
        }
        if (ReferenceEquals(_risksFor, _r)) return;
        var prev = System.Windows.Input.Mouse.OverrideCursor;
        System.Windows.Input.Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
        try
        {
            var rep = RiskViews.Build(_r, _cls);
            RisksInfo.Content = DetailsBuilder.Risks(Ctx(), rep);
            _risksFor = _r;
            SetStatus($"Risks: {rep.Writable.Count(w => !w.Explained):N0} unexplained writable places, "
                      + $"{rep.Runners.Count(x => x.WritableBy.Count > 0):N0} privileged programs non-admins can replace.");
        }
        catch (Exception ex) { SetStatus("Risk views failed: " + ex.Message, "Brush.Error"); }
        finally { System.Windows.Input.Mouse.OverrideCursor = prev; }
    }

    private DetailsContext Ctx() => new()
    {
        R = _r!, Kb = _ckb!, Cls = _cls!, Principals = _principals,
        CopyNodeForAi = CopyNodeForAi,
        CopySubtreeForAi = CopySubtreeForAi,
        CopyPrincipalForAi = CopyPrincipalForAi,
        Reveal = Reveal,
        ShowPrincipal = ShowPrincipal,
        CopyText = (text, msg) => { if (SetClipboard(text)) SetStatus(msg); },
        ResetWhyNot = n => ResetToInherit.WhyNot(_r!, n),
        StartReset = StartReset,
        PointToComponentCleanup = PointToComponentCleanup,
        StartDownloadMarks = StartDownloadMarks,
        CleanupWhyNot = () => OrphanCleanup.WhyNot(_r!),
        StartCleanup = StartCleanup,
        GrantWhyNot = () => ExplorerGrants.WhyNot(_r!),
        StartGrantUndo = StartGrantUndo,
    };

    // ---- explorer ------------------------------------------------------------------------

    private const int ExpandLimit = 5000;

    /// <summary>Expands the selected branch (or every drive) breadth-first until about 5,000 rows are showing.</summary>
    private void ExpandAll_Click(object sender, RoutedEventArgs e)
    {
        var start = Tree.SelectedItem is TreeItemVm sel ? new List<TreeItemVm> { sel } : _treeRoots.ToList();
        var queue = new Queue<TreeItemVm>(start);
        int rows = 0;
        bool stopped = false;
        while (queue.Count > 0)
        {
            var vm = queue.Dequeue();
            if (vm.Node.Children == null || !vm.Node.Children.Any(c => c.IsDirectory)) continue;
            vm.IsExpanded = true;
            foreach (var child in vm.Children.Where(c => c.ParentVm == vm))
            {
                if (++rows >= ExpandLimit) { stopped = true; break; }
                queue.Enqueue(child);
            }
            if (stopped) break;
        }
        SetStatus(stopped ? $"Expanded {ExpandLimit:N0} rows and stopped there — select a deeper folder and press + again to go on."
                          : $"Expanded {rows:N0} " + (rows == 1 ? "row." : "rows."), stopped ? "Brush.Warn" : "Brush.Ok");
    }

    /// <summary>Collapses everything back to the drives; the selection moves to its drive if it would be hidden.</summary>
    private void CollapseAll_Click(object sender, RoutedEventArgs e)
    {
        var selected = Tree.SelectedItem as TreeItemVm;
        var stack = new Stack<TreeItemVm>(_treeRoots);
        while (stack.Count > 0)
        {
            var vm = stack.Pop();
            foreach (var child in vm.Children.Where(c => c.ParentVm == vm)) stack.Push(child);
            vm.IsExpanded = false;
        }
        if (selected?.ParentVm != null)
        {
            var root = selected;
            while (root.ParentVm != null) root = root.ParentVm;
            selected.IsSelected = false;
            root.IsSelected = true;
        }
    }

    private void Tree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not TreeItemVm vm || _r == null) return;
        var node = vm.Node;
        ContentGrid.ItemsSource = node.Children?.Select(c => new NodeRowVm(c, _r)).ToList();
        ExplorerDetails.Content = DetailsBuilder.Node(Ctx(), node, offerReveal: false);
        ExplorerDetails.ScrollToTop();
    }

    private void ContentGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ContentGrid.SelectedItem is not NodeRowVm row || _r == null) return;
        ExplorerDetails.Content = DetailsBuilder.Node(Ctx(), row.Node, offerReveal: false);
        ExplorerDetails.ScrollToTop();
    }

    private void ContentGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ContentGrid.SelectedItem is NodeRowVm { Node.IsDirectory: true } row) Reveal(row.Node);
    }

    private void OnlyAttention_Changed(object sender, RoutedEventArgs e)
    {
        if (_r == null) return;
        var selected = (Tree.SelectedItem as TreeItemVm)?.Node;
        _treeRoots = _r.Roots.Select(n => new TreeItemVm(n, null, () => OnlyAttentionCheck.IsChecked == true)).ToList();
        Tree.ItemsSource = _treeRoots;
        if (selected != null) Reveal(selected, switchTab: false);
        else if (_treeRoots.Count > 0) _treeRoots[0].IsExpanded = true;
    }

    private IEnumerable<ScanNode> SelectedContentNodes() =>
        ContentGrid.SelectedItems.OfType<NodeRowVm>().Select(r => r.Node);

    private void CtxCopyAi_Click(object sender, RoutedEventArgs e)
    {
        var nodes = SelectedContentNodes().ToList();
        if (nodes.Count == 0 || _r == null) return;
        Deliver(Exporter().Nodes(nodes.Count == 1 ? nodes[0].FullPath : $"{nodes.Count} selected objects", nodes), "selection");
    }

    private void CtxCopyAiSubtree_Click(object sender, RoutedEventArgs e)
    {
        var node = SelectedContentNodes().FirstOrDefault();
        if (node != null) CopySubtreeForAi(node);
    }

    private void CtxCopyPath_Click(object sender, RoutedEventArgs e)
    {
        var paths = SelectedContentNodes().Select(n => n.FullPath).ToList();
        if (paths.Count > 0 && SetClipboard(string.Join(Environment.NewLine, paths))) SetStatus("Path copied.");
    }

    /// <summary>Selects an object in the Explorer tab (expanding the tree as needed).</summary>
    private void Reveal(ScanNode node) => Reveal(node, switchTab: true);

    private void Reveal(ScanNode node, bool switchTab)
    {
        if (_r == null) return;
        if (switchTab) Tabs.SelectedIndex = 0;
        var dir = node.IsDirectory ? node : node.Parent ?? node;
        var chain = new List<ScanNode> { dir };
        chain.AddRange(dir.Ancestors());
        chain.Reverse();

        if (OnlyAttentionCheck.IsChecked == true && chain.Skip(1).Any(n => n.SubtreeAttention == 0 && n.SubtreeLinks == 0))
            OnlyAttentionCheck.IsChecked = false; // rebuilds the tree via OnlyAttention_Changed

        var vm = _treeRoots.FirstOrDefault(t => t.Node == chain[0]);
        if (vm == null) return;
        var vmPath = new List<TreeItemVm> { vm };
        for (int i = 1; i < chain.Count; i++)
        {
            vm.IsExpanded = true;
            vm.EnsureChildren();
            var next = vm.Children.FirstOrDefault(c => c.Node == chain[i]);
            if (next == null) break;
            vm = next;
            vmPath.Add(vm);
        }
        vm.IsSelected = true;
        Dispatcher.InvokeAsync(() =>
        {
            BringTreeItemIntoView(vmPath);
            if (!node.IsDirectory && ContentGrid.ItemsSource is IEnumerable<NodeRowVm> rows)
            {
                var row = rows.FirstOrDefault(r => r.Node == node);
                if (row != null) { ContentGrid.SelectedItem = row; ContentGrid.ScrollIntoView(row); }
            }
        }, DispatcherPriority.Background);
    }

    private void BringTreeItemIntoView(List<TreeItemVm> path)
    {
        ItemsControl parent = Tree;
        TreeViewItem? container = null;
        foreach (var vm in path)
        {
            parent.ApplyTemplate();
            var presenter = FindVisualChild<ItemsPresenter>(parent);
            presenter?.ApplyTemplate();
            parent.UpdateLayout();
            container = parent.ItemContainerGenerator.ContainerFromItem(vm) as TreeViewItem;
            if (container == null)
            {
                int index = parent.Items.IndexOf(vm);
                if (index < 0) return;
                var panel = FindVisualChild<VirtualizingStackPanel>(parent);
                panel?.BringIndexIntoViewPublic(index);
                parent.UpdateLayout();
                container = parent.ItemContainerGenerator.ContainerFromIndex(index) as TreeViewItem;
            }
            if (container == null) return;
            if (vm != path[^1]) container.IsExpanded = true;
            parent = container;
        }
        container?.BringIntoView();
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T t) return t;
            var deeper = FindVisualChild<T>(child);
            if (deeper != null) return deeper;
        }
        return null;
    }

    // ---- findings: filter pills ---------------------------------------------------------------

    private void BuildFilterChips()
    {
        OriginChips.Children.Clear();
        CategoryChips.Children.Clear();
        CauseChips.Children.Clear();
        _originChips.Clear();
        _categoryChips.Clear();
        _causeChips.Clear();
        var all = _r?.Findings ?? new List<Finding>();

        var byOrigin = all.GroupBy(f => f.Origin).ToDictionary(g => g.Key, g => g.Count());
        foreach (var o in FilterOrigins)
        {
            int n = byOrigin.GetValueOrDefault(o);
            var chip = Chip("Hue.PillToggle.Tag", Ui.TagStyleKey(o), $"{OriginText.Label(o)} {n:N0}", o.ToString(), n,
                $"{OriginText.Label(o)}: none in this scan");
            chip.IsChecked = n > 0 && DefaultLitOrigins.Contains(o);
            _originChips.Add(chip);
            OriginChips.Children.Add(chip);
        }

        var byCat = all.GroupBy(f => f.Category).ToDictionary(g => g.Key, g => g.Count());
        foreach (var cat in Enum.GetValues<FindingCategory>())
        {
            int n = byCat.GetValueOrDefault(cat);
            var chip = Chip("Hue.PillToggle.Tag", "Hue.Tag", $"{OriginText.Label(cat)} {n:N0}", cat.ToString(), n,
                $"{OriginText.Label(cat)}: none in this scan");
            if (cat == FindingCategory.ExplorerGrant && n > 0)
            {
                // the one kind that is always a risk gets the alarm colour on its pill too
                chip.Content = new ContentControl { Style = (Style)FindResource("Hue.Tag.Unsafe"), Content = $"{OriginText.Label(cat)} {n:N0}" };
                chip.ToolTip = "Permanent full-control entries left by Explorer's \"Continue\" button.";
            }
            if (cat == FindingCategory.Link && n > 0)
                chip.ToolTip = "Junctions and symbolic links. Lit, it shows every link — stock ones included — whatever the origin filter says.";
            _categoryChips.Add(chip);
            CategoryChips.Children.Add(chip);
        }
        var byCause = all.Where(f => f.Cause != null).GroupBy(f => f.Cause!.Value).ToDictionary(g => g.Key, g => g.Count());
        foreach (var cause in Enum.GetValues<ReadCause>())
        {
            int n = byCause.GetValueOrDefault(cause);
            if (n == 0) continue;
            var chip = Chip("Hue.PillToggle.Tag", "Hue.Tag", $"{ReadCauses.Label(cause)} {n:N0}", cause.ToString(), n, "");
            chip.ToolTip = ReadCauses.Explain(cause);
            _causeChips.Add(chip);
            CauseChips.Children.Add(chip);
        }
        CausePanel.Visibility = _causeChips.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        HuePill.Dim(_originChips);
        HuePill.Dim(_categoryChips);
        HuePill.Dim(_causeChips);
    }

    private void UpdateGrantNotice()
    {
        int n = _r?.Findings.Count(f => f.Category == FindingCategory.ExplorerGrant) ?? 0;
        GrantNotice.Visibility = n > 0 ? Visibility.Visible : Visibility.Collapsed;
        GrantNotice.Content = n == 1 ? "1 Explorer grant" : $"{n:N0} Explorer grants";
        AutomationProperties.SetName(GrantNotice, GrantNotice.Content as string ?? "Explorer grants");
    }

    private void UpdateSxsNotice()
    {
        var pv = _r is { IsLive: true } ? ComponentCleanup.Preview(_r) : null;
        int n = pv?.Components ?? 0;
        SxsNotice.Visibility = n > 0 ? Visibility.Visible : Visibility.Collapsed;
        SxsNotice.Content = $"WinSxS: {n:N0} superseded component{(n == 1 ? "" : "s")}";
        AutomationProperties.SetName(SxsNotice, SxsNotice.Content as string ?? "WinSxS");
    }

    /// <summary>Jumps to WinSxS in the Explorer tab, where the clean-up is.</summary>
    private void SxsNotice_Click(object sender, RoutedEventArgs e)
    {
        if (_r == null || ComponentCleanup.WinSxSPath(_r) is not { } path || _r.FindByPath(path) is not { } node) return;
        Reveal(node);
    }

    /// <summary>The button in the action row: works without a scan, so it can run before a full scan. Asks first.</summary>
    private async void ComponentCleanup_Click(object sender, RoutedEventArgs e)
    {
        if (!MayAct()) return;
        if (ComponentCleanup.WhyNot() is { } why) { HueMessage.Show(this, "Component store clean-up", why); return; }
        var pv = _r is { IsLive: true } ? ComponentCleanup.Preview(_r) : null;
        var message =
            "Runs Windows' own clean-up of the component store (WinSxS): dism.exe /Online /Cleanup-Image /StartComponentCleanup — "
            + "the step Windows' scheduled servicing task runs 30 days after an update, now. It removes superseded component "
            + "versions; which ones is DISM's decision.\n\n"
            + (pv is { OlderVersions: > 0 } ? $"The current scan sees {pv.OlderVersions:N0} older versions of {pv.Components:N0} components ({Ui.Size(pv.Size)} as listed).\n\n" : "")
            + "Run it before a full scan: the scan then does not have to read the superseded versions.\n\n"
            + "With /ResetBase every superseded version goes for good: installed updates can no longer be uninstalled. That is not reversible.\n\n"
            + "Once started, DISM is not interrupted, and the window stays open until it has finished.";
        var choice = HueMessage.Choose(this, "Component store clean-up", message,
            "Clean up with /ResetBase", "Clean up", "Cancel", destructive: true);
        if (choice == HueChoice.Cancel) return;
        await DoComponentCleanup(resetBase: choice == HueChoice.Yes);
    }

    /// <summary>Runs Windows' component-store clean-up on this Windows. No cancel button: DISM is never interrupted. With a
    /// live scan loaded, WinSxS is read again afterwards; otherwise only DISM's result is shown.</summary>
    private async Task DoComponentCleanup(bool resetBase)
    {
        if (ComponentCleanup.WhyNot() is { } why) { SetStatus(why, "Brush.Warn"); return; }
        var r = _r is { IsLive: true } ? _r : null;
        var kb = _kb;
        var sxs = r != null && ComponentCleanup.WinSxSPath(r) is { } path ? r.FindByPath(path) : null;
        int before = sxs != null ? ComponentCleanup.CountObjects(sxs) : 0;
        BeginRunning("The component store clean-up", cancelable: false);
        try
        {
            var (done, outcome) = await Busy.RunAsync("Cleaning up the component store", report =>
            {
                report.Say("dism.exe " + ComponentCleanup.Arguments(resetBase));
                var (code, output) = ComponentCleanup.Run(resetBase, (text, pct) => report.Say(text, pct, pct != null ? 100 : null));
                Classified? classified = null;
                int after = 0;
                if (r != null && sxs != null)
                {
                    report.Say("Reading WinSxS again…");
                    Scanner.Relist(r, sxs, k => report.Say($"Reading WinSxS again… {k:N0} objects"));
                    after = ComponentCleanup.CountObjects(sxs);
                    classified = Classify(r, kb, report);
                }
                return (classified, new DismOutcome(code, output, before, after));
            });
            if (done != null)
            {
                Apply(done);
                if (sxs != null) Reveal(sxs);
            }
            var ok = outcome.ExitCode == 0;
            var gone = outcome.ObjectsBefore - outcome.ObjectsAfter;
            var counted = done != null
                ? $"WinSxS: {outcome.ObjectsBefore:N0} objects before, {outcome.ObjectsAfter:N0} after ({gone:N0} fewer)."
                : "No live scan is loaded, so nothing was counted. A scan from now on reads the cleaned store.";
            SetStatus(ok ? "Component store clean-up done. " + counted : $"DISM ended with code {outcome.ExitCode}. " + counted,
                ok ? "Brush.Ok" : "Brush.Warn");
            HueMessage.Show(this, ok ? "Component store clean-up done" : "Component store clean-up ended with an error",
                $"dism.exe {ComponentCleanup.Arguments(resetBase)}\nExit code {outcome.ExitCode}.\n\n{counted}\n\n"
                + (outcome.Output.Length > 0 ? "DISM said:\n" + string.Join("\n", outcome.Output.Split('\n').TakeLast(12)) : ""));
        }
        catch (Exception ex)
        {
            SetStatus("Component store clean-up failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Component store clean-up failed", ex.Message);
        }
        finally { EndRunning(); }
    }

    // ================================================================================== download marks

    /// <summary>Step 1: reads the marks below the folder and shows the preview. Nothing is written.</summary>
    private async void StartDownloadMarks(ScanNode folder)
    {
        if (!MayAct()) return;
        if (_r == null) return;
        if (DownloadMarks.WhyNot(_r, folder) is { } why) { SetStatus(why, "Brush.Warn"); return; }
        var r = _r;
        MarksPlan? plan;
        using var cancel = new CancellationTokenSource();
        try
        {
            plan = await Busy.RunAsync("Reading download marks below " + folder.FullPath, report =>
                DownloadMarks.Plan(r, folder, (path, i, n) => report.Say(path, i, n), cancel.Token), cancel);
        }
        catch (Exception ex)
        {
            SetStatus("Download marks: " + ex.Message, "Brush.Error");
            return;
        }
        if (plan == null)
        {
            SetStatus("Download marks: reading cancelled — nothing was changed.");
            return;
        }
        Tabs.SelectedIndex = 0;
        ExplorerDetails.Content = DetailsBuilder.MarksPreview(plan, files => _ = DoDownloadMarks(plan, files), () =>
        {
            Reveal(folder);
            SetStatus("Download marks: cancelled — nothing was changed.");
        });
        ExplorerDetails.ScrollToTop();
        SetStatus($"Download marks below {folder.FullPath}: {plan.DataCount:N0} on data files, {plan.ProgramCount:N0} on programs and scripts — see the preview.");
    }

    /// <summary>Step 2: removes the chosen marks, then reads the folder again.</summary>
    private async Task DoDownloadMarks(MarksPlan plan, IReadOnlyList<MarkedFile> files)
    {
        if (_r == null || files.Count == 0) return;
        var r = _r;
        var kb = _kb;
        using var cancel = new CancellationTokenSource();
        BeginRunning("Removing download marks", cancelable: true);
        try
        {
            var (done, o) = await Busy.RunAsync("Removing download marks", report =>
            {
                var outcome = DownloadMarks.Run(files, (path, i, n) => report.Say(path, i, n), cancel.Token);
                report.Say("Reading " + plan.Folder.FullPath + " again…");
                Scanner.Relist(r, plan.Folder, k => report.Say($"Reading again… {k:N0} objects"));
                return (Classify(r, kb, report), outcome);
            }, cancel);
            Apply(done);
            Tabs.SelectedIndex = 0;
            ExplorerDetails.Content = DetailsBuilder.MarksResult(plan.Folder, files.Count, o, () => Reveal(plan.Folder));
            ExplorerDetails.ScrollToTop();
            var text = $"{o.Removed:N0} of {Ui.Count(files.Count, "mark")} removed."
                       + (o.AlreadyGone > 0 ? $" {o.AlreadyGone:N0} were already gone." : "")
                       + (o.Cancelled ? " Stopped before the end — the rest keep their marks." : "")
                       + (o.Failed.Count > 0 ? $" {o.Failed.Count:N0} could not be removed — the list is in the details panel." : "");
            SetStatus($"Download marks: {o.Removed:N0} removed" + (o.Failed.Count > 0 ? $", {o.Failed.Count:N0} could not be removed." : "."),
                o.Failed.Count > 0 || o.Cancelled ? "Brush.Warn" : "Brush.Ok");
            HueMessage.Show(this, "Download marks", text);
        }
        catch (Exception ex)
        {
            SetStatus("Removing download marks failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Removing download marks failed", ex.Message);
        }
        finally { EndRunning(); }
    }

    // ================================================================================== superseded app versions

    /// <summary>Step 1: asks Windows who still uses each older package version and shows the preview. Nothing is changed.</summary>
    private async void AppVersions_Click(object sender, RoutedEventArgs e)
    {
        if (!MayAct()) return;
        if (AppVersions.WhyNot() is { } why) { HueMessage.Show(this, "Superseded app versions", why); return; }
        AppVersionsPlan plan;
        try
        {
            plan = await Busy.RunAsync("Asking Windows about older app versions", report => AppVersions.Plan(s => report.Say(s)));
        }
        catch (Exception ex)
        {
            SetStatus("Superseded app versions: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Superseded app versions", ex.Message);
            return;
        }
        Tabs.SelectedIndex = 0;
        ExplorerDetails.Content = DetailsBuilder.AppVersionsPreview(plan, (remove, delete) => _ = DoAppVersions(plan, remove, delete), () =>
        {
            ExplorerDetails.Content = null;
            SetStatus("Superseded app versions: cancelled — nothing was changed.");
        });
        ExplorerDetails.ScrollToTop();
        SetStatus($"Superseded app versions: {plan.Unused.Count():N0} unused, {plan.NotKnown.Count():N0} not known to Windows, "
                  + $"{plan.Used.Count():N0} still used — see the preview.");
    }

    /// <summary>Step 2: Windows removes the chosen unused versions; the chosen leftover folders are deleted.</summary>
    private async Task DoAppVersions(AppVersionsPlan plan, IReadOnlyList<AppVersionItem> remove, IReadOnlyList<AppVersionItem> delete)
    {
        var r = _r is { IsLive: true } ? _r : null;
        var kb = _kb;
        using var cancel = new CancellationTokenSource();
        BeginRunning("Removing superseded app versions", cancelable: true);
        try
        {
            var (done, o) = await Busy.RunAsync("Removing superseded app versions", report =>
            {
                var outcome = AppVersions.Run(remove, delete, (text, i, n) => report.Say(text, i, n), cancel.Token);
                Classified? classified = null;
                if (r != null && r.FindByPath(plan.WindowsApps) is { } wa)
                {
                    report.Say("Reading WindowsApps again…");
                    Scanner.Relist(r, wa, k => report.Say($"Reading WindowsApps again… {k:N0} objects"));
                    classified = Classify(r, kb, report);
                }
                return (classified, outcome);
            }, cancel);
            if (done != null) Apply(done);
            Tabs.SelectedIndex = 0;
            ExplorerDetails.Content = DetailsBuilder.AppVersionsResult(o, remove.Count, delete.Count);
            ExplorerDetails.ScrollToTop();
            var text = (o.Checked
                           ? $"Checked afterwards: {o.Gone:N0} removed and gone, {o.OnDisk:N0} removed but the folder is still on disk, "
                             + $"{o.NotRemoved:N0} not removed."
                           : "Windows could not be asked again afterwards, so nothing is counted as removed.")
                       + (delete.Count > 0 ? $" {o.FoldersDeleted:N0} of {Ui.Count(delete.Count, "leftover folder")} deleted." : "")
                       + (o.BytesFreed > 0 ? $" {Ui.Size(o.BytesFreed)} freed — only what is gone from disk." : " Nothing was freed.")
                       + (o.Cancelled ? " Stopped before the end — the rest is unchanged." : "")
                       + "\n\nEvery version with its route, Windows' answer and the check is in the panel on the right.";
            SetStatus($"Superseded app versions: {o.Gone:N0} removed and gone, {o.OnDisk:N0} folder(s) still on disk, {o.NotRemoved:N0} not removed, "
                      + $"{o.FoldersDeleted:N0} leftover folders deleted.",
                o.NotRemoved + o.OnDisk > 0 || o.Failed.Count > 0 || o.Cancelled || !o.Checked ? "Brush.Warn" : "Brush.Ok");
            HueMessage.Show(this, "Superseded app versions", text);
        }
        catch (Exception ex)
        {
            SetStatus("Superseded app versions failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Superseded app versions failed", ex.Message);
        }
        finally { EndRunning(); }
    }

    /// <summary>Opens Findings filtered to exactly the Explorer grants.</summary>
    private void GrantNotice_Click(object sender, RoutedEventArgs e)
    {
        foreach (var c in _categoryChips) c.IsChecked = HuePill.GetKey(c) == nameof(FindingCategory.ExplorerGrant);
        foreach (var c in _originChips) if (c.IsEnabled) c.IsChecked = true;
        Tabs.SelectedIndex = 1;
        _ = ApplyFindingFilter();
    }

    private ToggleButton Chip(string toggleStyle, string tagStyle, string text, string key, int count, string noneTip)
    {
        var chip = new ToggleButton
        {
            Style = (Style)FindResource(toggleStyle),
            Content = new ContentControl { Style = (Style)FindResource(tagStyle), Content = text },
            Margin = new Thickness(0, 0, 8, 6),
        };
        HuePill.SetKey(chip, key);
        AutomationProperties.SetName(chip, count == 0 ? noneTip.Replace(": none in this scan", ", none") : text);
        if (count == 0)
        {
            chip.IsEnabled = false;
            chip.ToolTip = noneTip;
            ToolTipService.SetShowOnDisabled(chip, true);
        }
        chip.Click += Chip_Click;
        return chip;
    }

    private void Chip_Click(object sender, RoutedEventArgs e)
    {
        // The pre-selection filters as usual. A pill switched on while nothing it stands for lies inside the current
        // selection clears the other rows, so the list shows what was clicked instead of nothing.
        if (sender is ToggleButton chip && chip.IsChecked == true && HuePill.GetKey(chip) is { } key)
        {
            var row = _originChips.Contains(chip) ? PillRow.Origin : _categoryChips.Contains(chip) ? PillRow.Kind : PillRow.Cause;
            if (FindingFilter.NothingInside(_allFindingRows, row, key, PillKeys(_originChips), PillKeys(_categoryChips), PillKeys(_causeChips)))
            {
                if (row != PillRow.Origin) foreach (var c in _originChips) c.IsChecked = false;
                if (row != PillRow.Kind) foreach (var c in _categoryChips) c.IsChecked = false;
                if (row != PillRow.Cause) foreach (var c in _causeChips) c.IsChecked = false;
            }
        }
        HuePill.Dim(_originChips);
        HuePill.Dim(_categoryChips);
        HuePill.Dim(_causeChips);
        _ = ApplyFindingFilter();
    }

    private void FilterText_Changed(object sender, TextChangedEventArgs e)
    {
        _filterDebounce.Stop();
        _filterDebounce.Start();
    }

    private static List<(string Key, bool Lit)> PillKeys(List<ToggleButton> chips) =>
        chips.Select(c => (HuePill.GetKey(c) ?? "", c.IsChecked == true)).ToList();

    private async Task ApplyFindingFilter()
    {
        var origins = PillKeys(_originChips);
        var cats = PillKeys(_categoryChips);
        var causes = PillKeys(_causeChips);
        var text = FText.Text?.Trim() ?? "";
        var all = _allFindingRows;
        int version = ++_filterVersion;
        FindingCount.Text = "Filtering…";
        var rows = await Task.Run(() => all.Where(r => FindingFilter.Passes(r, origins, cats, causes, text)).ToList());
        if (version != _filterVersion) return;
        FindingsGrid.ItemsSource = rows;
        FindingCount.Text = $"{rows.Count:N0} of {all.Count:N0} findings";
    }

    private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not FindingRowVm row || _r == null) return;
        FindingDetails.Content = DetailsBuilder.Node(Ctx(), row.Finding.Node, offerReveal: true);
        FindingDetails.ScrollToTop();
    }

    private void FindingsGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (FindingsGrid.SelectedItem is FindingRowVm row) Reveal(row.Finding.Node);
    }

    private void RevealFinding_Click(object sender, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is FindingRowVm row) Reveal(row.Finding.Node);
    }

    private void CopyFindingPath_Click(object sender, RoutedEventArgs e)
    {
        var paths = FindingsGrid.SelectedItems.OfType<FindingRowVm>().Select(r => r.Path).Distinct().ToList();
        if (paths.Count > 0 && SetClipboard(string.Join(Environment.NewLine, paths))) SetStatus("Path copied.");
    }

    private void CopySelectedFindings_Click(object sender, RoutedEventArgs e)
    {
        var findings = FindingsGrid.SelectedItems.OfType<FindingRowVm>().Select(r => r.Finding).ToList();
        if (findings.Count == 0 || _r == null) return;
        var nodes = findings.Select(f => f.Node).Distinct().ToList();
        Deliver(Exporter().Nodes($"{findings.Count} selected findings", nodes, findings), "selected-findings");
    }

    private (List<Finding> Findings, List<ScanNode> Nodes)? FilteredSet()
    {
        if (_r == null || FindingsGrid.ItemsSource is not List<FindingRowVm> rows) return null;
        var findings = rows.Select(r => r.Finding).ToList();
        return (findings, findings.Select(f => f.Node).Distinct().ToList());
    }

    private string FilterDescription()
    {
        string Lit(List<ToggleButton> chips) => string.Join("/", chips.Where(c => c.IsChecked == true).Select(c => HuePill.GetKey(c)));
        var o = Lit(_originChips);
        var k = Lit(_categoryChips);
        var c = Lit(_causeChips);
        var t = string.IsNullOrWhiteSpace(FText.Text) ? "" : $", matching \"{FText.Text.Trim()}\"";
        return $"filtered findings (origin: {(o.Length == 0 ? "all" : o)}; kind: {(k.Length == 0 ? "all" : k)}"
               + (c.Length > 0 ? $"; unreadable cause: {c}" : "") + $"{t})";
    }

    private void CopyFiltered_Click(object sender, RoutedEventArgs e)
    {
        if (FilteredSet() is not { } set) return;
        Deliver(Exporter().Nodes(FilterDescription(), set.Nodes, set.Findings), "findings");
    }

    private void SaveFiltered_Click(object sender, RoutedEventArgs e)
    {
        if (FilteredSet() is not { } set) return;
        Deliver(Exporter().Nodes(FilterDescription(), set.Nodes, set.Findings), "findings", forceFile: true);
    }

    // ---- principals ------------------------------------------------------------------------

    private void BuildPrincipals()
    {
        if (_r == null || _ckb == null || _cls == null) return;
        var sids = new HashSet<string>(_r.Names.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var u in _r.Inventory.Users) if (u.Sid != null) sids.Add(u.Sid);
        foreach (var g in _r.Inventory.Groups) if (g.Sid != null) sids.Add(g.Sid);
        foreach (var s in _cls.ExplicitRefs.Keys) sids.Add(s);
        foreach (var s in _r.Inventory.AccountTraces.Keys) sids.Add(s);
        // SIDs that occur in any security descriptor (as owner, group or entry) — a deleted account that occurs in none is
        // only a lingering record.
        var inDescriptors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in _r.Descriptors.Snapshot())
            foreach (var s in new SdInfo(raw).AllSids())
                if (!string.IsNullOrEmpty(s)) inDescriptors.Add(s);

        var list = new List<PrincipalRowVm>();
        foreach (var sid in sids.Where(s => !string.IsNullOrEmpty(s)))
        {
            var p = _r.NameOf(sid);
            var entry = _ckb.Principal(sid);
            var orphan = _cls.OrphanStateOf(sid);
            Origin origin; string explain; string? kbId;
            if (SidText.SplitAccountSid(sid) != null)
            {
                (origin, explain, kbId) = _cls.ClassifyAccount(p.Name, sid);
                if (orphan == OrphanState.Proven)
                {
                    origin = Origin.Custom;
                    explain = "Orphaned SID: Windows confirms no account has this SID any more (deleted, or from an earlier installation, "
                              + "another machine or a previous domain). Entries for it and objects it owns are leftovers.";
                }
                else if (orphan == OrphanState.Unverifiable)
                {
                    origin = Origin.Unknown;
                    explain = $"Could not be checked: the lookup failed with error {p.LookupError} ({Classifier.Win32Message(p.LookupError)}), "
                              + "usually because the domain controller was unreachable. The account may well exist.";
                }
            }
            else if (entry != null)
            {
                origin = entry.Sid != null
                    ? (entry.Builtin ? Origin.Stock : entry.OriginValue)
                    : (entry.Origin != null ? entry.OriginValue : Origin.Unknown);
                explain = entry.Explain ?? "";
                kbId = "principals/" + entry.Id;
            }
            else { origin = Origin.Unknown; explain = ""; kbId = null; }

            int explicitN = _cls.ExplicitRefs.TryGetValue(sid, out var refs0) ? refs0.Count : 0;
            int ownerN = _cls.OwnerCounts.GetValueOrDefault(sid);
            bool traceOnly = orphan == OrphanState.Proven && explicitN == 0 && ownerN == 0
                             && _r.Inventory.AccountTraces.ContainsKey(sid) && !inDescriptors.Contains(sid);
            bool groupOnly = !traceOnly && orphan == OrphanState.Proven && explicitN == 0 && ownerN == 0;
            if (traceOnly)
            {
                origin = Origin.Trace;
                explain = "A deleted account that Windows still remembers outside its account database — no entries, owns nothing, "
                          + "so it grants nothing. Where it lingers is listed below. Windows offers no supported removal for these "
                          + "records; they go with a reinstall. App registrations of deleted accounts show in Superseded app versions.";
            }
            else if (groupOnly)
            {
                origin = Origin.Trace;
                explain = "Orphaned SID that appears only as the primary group of some objects — no entries, owns nothing. Windows ignores "
                          + "the primary group when deciding access, so it grants nothing and needs no clean-up. It usually comes with "
                          + "files created on another Windows installation (\"None\"/Domain Users of that machine).";
            }
            list.Add(new PrincipalRowVm
            {
                Sid = sid,
                Name = p.Resolved ? p.Display : Ui.UnnamedCapability(sid) ?? entry?.Name ?? sid,
                Kind = PrincipalKinds.Describe(sid, p, _r, _ckb, orphan) + (traceOnly ? " (lingering trace)" : groupOnly ? " (primary group only)" : ""),
                Origin = origin, Explain = explain, KbId = kbId, Orphan = orphan,
                ExplicitCount = _cls.ExplicitRefs.TryGetValue(sid, out var refs) ? refs.Count : 0,
                OwnerCount = _cls.OwnerCounts.GetValueOrDefault(sid),
            });
        }
        int Rank(PrincipalRowVm r) => r.Kind switch
        {
            "Local user" => 0, "Local group" => 1, "Built-in group" => 2, "Domain user" => 3, "Domain group" => 4,
            "Orphaned SID" => 5, "Unverifiable SID" => 6, "Well-known" => 7, "IIS app pool" => 8, "Service" => 9, _ => 10,
        };
        _principals = list.OrderBy(Rank).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void PrincipalFilter_Changed(object sender, RoutedEventArgs e) => ApplyPrincipalFilter();

    private void ApplyPrincipalFilter()
    {
        var text = PrincipalFilter.Text?.Trim() ?? "";
        bool refsOnly = PrincipalReferencedOnly.IsChecked == true;
        bool orphansOnly = PrincipalOrphansOnly.IsChecked == true;
        PrincipalGrid.ItemsSource = _principals.Where(p =>
            (!refsOnly || p.ExplicitCount > 0) &&
            (!orphansOnly || p.Orphan != OrphanState.None) &&
            (text.Length == 0 || p.Name.Contains(text, StringComparison.OrdinalIgnoreCase) || p.Sid.Contains(text, StringComparison.OrdinalIgnoreCase)
             || p.Kind.Contains(text, StringComparison.OrdinalIgnoreCase))).ToList();
    }

    private void PrincipalGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PrincipalGrid.SelectedItem is not PrincipalRowVm row || _r == null) return;
        PrincipalDetails.Content = DetailsBuilder.Principal(Ctx(), row);
        PrincipalDetails.ScrollToTop();
    }

    private void ShowPrincipal(string sid)
    {
        if (_r == null) return;
        Tabs.SelectedIndex = 2;
        var row = _principals.FirstOrDefault(p => string.Equals(p.Sid, sid, StringComparison.OrdinalIgnoreCase));
        if (row == null) return;
        if (PrincipalGrid.ItemsSource is not List<PrincipalRowVm> visible || !visible.Contains(row))
        {
            PrincipalFilter.Text = "";
            PrincipalReferencedOnly.IsChecked = false;
            PrincipalOrphansOnly.IsChecked = false;
            ApplyPrincipalFilter();
        }
        PrincipalGrid.SelectedItem = row;
        PrincipalGrid.ScrollIntoView(row);
    }

    // ---- shares ---------------------------------------------------------------------------

    private void ShareGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ShareGrid.SelectedItem is not ShareRowVm row || _r == null) return;
        ShareDetails.Content = DetailsBuilder.Share(Ctx(), row);
        ShareDetails.ScrollToTop();
    }

    private void CopyShares_Click(object sender, RoutedEventArgs e)
    {
        if (_r == null) return;
        Deliver(Exporter().Shares(_r.Inventory.Shares), "shares");
    }

    // ================================================================================== other Windows installations

    /// <summary>Asks, for every place the action would change something in that may be another Windows installation or
    /// image (a folder holding Windows\System32 other than this Windows, or an image DISM records as mounted), whether it
    /// is one. Nothing is assumed: no place found, no question. Returns the places to leave alone, or null when cancelled.</summary>
    private List<string>? AskAboutOtherWindows(IEnumerable<ScanNode> touched)
    {
        var leave = new List<string>();
        if (_r == null) return leave;
        foreach (var place in ForeignWindows.Touching(ForeignWindows.Find(_r), touched))
        {
            var choice = HueMessage.Choose(this, "Another Windows installation or image?",
                $"{place.Path} {place.Evidence}.\n\nThis action would change something there. Is it a separate Windows "
                + "installation or image — a second Windows, Windows.old, an image mounted with DISM?\n\n"
                + $"Separate: everything in {place.Path} is left alone and shown as not touched.\n"
                + "Not separate: it is handled like any other folder.",
                "Not separate — include it", "Separate — leave it alone", "Cancel", destructive: true);
            if (choice == HueChoice.Cancel) return null;
            if (choice == HueChoice.No) leave.Add(place.Path);
        }
        return leave;
    }

    // ================================================================================== reset to inherit

    /// <summary>Step 1: show what would change, in the Explorer details panel. Nothing is written.</summary>
    private void StartReset(ScanNode target)
    {
        if (!MayAct()) return;
        if (_r == null) return;
        if (ResetToInherit.WhyNot(_r, target) is { } why) { SetStatus(why, "Brush.Warn"); return; }
        var plan = ResetToInherit.Plan(_r, target);
        if (AskAboutOtherWindows(plan.Change) is not { } leave) { SetStatus("Reset cancelled — nothing was changed."); return; }
        if (leave.Count > 0) plan = ResetToInherit.Plan(_r, target, leave);
        Reveal(target);
        Dispatcher.InvokeAsync(() =>
        {
            ExplorerDetails.Content = DetailsBuilder.ResetPreview(Ctx(), plan, () => _ = DoReset(plan), () =>
            {
                ExplorerDetails.Content = DetailsBuilder.Node(Ctx(), target, offerReveal: false);
                SetStatus("Reset cancelled — nothing was changed.");
            });
            ExplorerDetails.ScrollToTop();
        }, DispatcherPriority.Background);
    }

    /// <summary>Step 2: backup file (asked, written, verified), then the change, then re-read and re-classify.</summary>
    private async Task DoReset(ResetPlan plan)
    {
        if (_r == null) return;
        var safeName = string.Concat(plan.Target.FullPath.Select(ch => char.IsLetterOrDigit(ch) ? ch : '-')).Trim('-');
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save a backup of the current permissions before resetting",
            Filter = "icacls backup (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"AclLegibility-backup-{safeName}-{DateTime.Now:yyyyMMdd-HHmm}.txt",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        if (dlg.ShowDialog(this) != true) { SetStatus("Reset cancelled — no backup chosen, nothing was changed."); return; }
        var file = dlg.FileName;
        var r = _r;
        var kb = _kb;
        using var cancel = new CancellationTokenSource();
        BeginRunning("Reset to inherit", cancelable: true);
        try
        {
            var (done, outcome) = await Busy.RunAsync("Resetting " + plan.Target.FullPath + " to inherit", report =>
            {
                report.Say("Writing and checking the backup…");
                ResetToInherit.WriteBackup(r, plan, file);   // throws before anything is changed
                var o = ResetToInherit.Run(plan, (i, total, path) => report.Say(path, i, total), cancel.Token);
                report.Say("Reading the result…");
                Scanner.Reprobe(r, plan.Target, k => report.Say($"Reading the result… {k:N0} objects"));
                return (Classify(r, kb, report), o);
            }, cancel);

            Apply(done);
            Reveal(plan.Target);
            var text = $"{outcome.Changed:N0} of {plan.Change.Count:N0} objects now inherit their permissions."
                       + (outcome.Cancelled ? " Stopped before the end — the rest is unchanged." : "")
                       + (outcome.Failed.Count > 0 ? $" {outcome.Failed.Count:N0} could not be changed:\n"
                          + string.Join("\n", outcome.Failed.Take(8).Select(f => $"  {f.Path} — error {f.Error}: {Classifier.Win32Message(f.Error)}"))
                          + (outcome.Failed.Count > 8 ? $"\n  … and {outcome.Failed.Count - 8:N0} more" : "") : "")
                       + $"\n\nBackup of the previous permissions:\n{file}\n\nTo restore them, run in an elevated PowerShell:\n{ResetToInherit.RestoreCommand(plan, file)}";
            SetStatus($"Reset to inherit: {outcome.Changed:N0} objects changed. Backup: {file}", outcome.Failed.Count > 0 || outcome.Cancelled ? "Brush.Warn" : "Brush.Ok");
            HueMessage.Show(this, "Reset to inherit done", text);
        }
        catch (Exception ex)
        {
            SetStatus("Reset failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Reset to inherit failed", ex.Message
                + (File.Exists(file) ? $"\n\nIf anything was changed, the backup is here:\n{file}\n\nRestore with:\n{ResetToInherit.RestoreCommand(plan, file)}" : ""));
        }
        finally { EndRunning(); }
    }

    // ================================================================================== orphan cleanup

    private void CleanAll_Click(object sender, RoutedEventArgs e)
    {
        var sids = _principals.Where(p => p.Orphan == OrphanState.Proven).Select(p => p.Sid).ToList();
        if (sids.Count == 0) { SetStatus("No proven orphaned SIDs in this scan."); return; }
        StartCleanup(sids);
    }

    /// <summary>Step 1: preview in the Accounts & groups details panel. Nothing is written.</summary>
    private void StartCleanup(IReadOnlyCollection<string> sids)
    {
        if (!MayAct()) return;
        if (_r == null || _cls == null || _ckb == null) return;
        if (OrphanCleanup.WhyNot(_r) is { } why) { SetStatus(why, "Brush.Warn"); return; }
        var plan = OrphanCleanup.Plan(_r, _cls, _ckb, sids);
        if (AskAboutOtherWindows(plan.Touched) is not { } leave) { SetStatus("Clean-up cancelled — nothing was changed."); return; }
        if (leave.Count > 0) plan = OrphanCleanup.Plan(_r, _cls, _ckb, sids, leave);
        Tabs.SelectedIndex = 2;
        PrincipalDetails.Content = DetailsBuilder.OrphanPreview(Ctx(), plan, zip => _ = DoCleanup(plan, plan.Profiles, zip), () =>
        {
            PrincipalDetails.Content = null;
            SetStatus("Clean-up cancelled — nothing was changed.");
        });
        PrincipalDetails.ScrollToTop();
    }

    /// <summary>Step 2: backups (asked, written, verified) when entries change, then the change, then re-read and re-classify.</summary>
    private async Task DoCleanup(OrphanPlan plan, IReadOnlyList<ProfilePlan> profiles, bool zip)
    {
        if (_r == null) return;
        string? zipFile = null;
        if (zip)
        {
            var zd = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save the personal files of the profiles before they are deleted",
                Filter = "ZIP archive (*.zip)|*.zip",
                FileName = $"AclLegibility-profiles-{DateTime.Now:yyyyMMdd-HHmm}.zip",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            };
            if (zd.ShowDialog(this) != true) { SetStatus("Clean-up cancelled — no ZIP location chosen, nothing was changed."); return; }
            zipFile = zd.FileName;
        }
        string? chosen = null;
        if (plan.Entries.Count > 0)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save a backup of the entries that change before cleaning up",
                Filter = "icacls backup (*.txt)|*.txt|All files (*.*)|*.*",
                FileName = $"AclLegibility-orphans-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            };
            if (dlg.ShowDialog(this) != true) { SetStatus("Clean-up cancelled — no backup chosen, nothing was changed."); return; }
            chosen = dlg.FileName;
        }
        var files = chosen != null ? OrphanCleanup.BackupFiles(plan, chosen) : new();
        // A ZIP or backup saved inside something the clean-up deletes would be deleted with it.
        foreach (var path in new[] { zipFile }.Concat(files.SelectMany(f => new[] { f.File, IcaclsBackup.RootFile(f.File) })))
        {
            if (path == null || OrphanCleanup.DoomedHolder(plan, profiles, path) is not { } holder) continue;
            HueMessage.Show(this, "Choose another place", $"{path}\n\nlies in\n{holder}\n\nwhich this clean-up deletes, so the file would be "
                                                          + "deleted with it. Choose a place outside it.");
            SetStatus("Clean-up cancelled — the ZIP or backup would have been deleted with the rest, nothing was changed.");
            return;
        }
        (int Files, long Bytes) zipSaved = (0, 0);
        var r = _r;
        var kb = _kb;
        using var cancel = new CancellationTokenSource();
        BeginRunning("The orphan clean-up", cancelable: true);
        try
        {
            var (done, outcome) = await Busy.RunAsync("Cleaning up orphaned SIDs", report =>
            {
                (int Files, long Bytes) saved = (0, 0);
                if (zipFile != null)
                {
                    report.Say("Saving personal files to the ZIP and checking it…");
                    saved = ProfileBackup.Write(zipFile, profiles.Where(x => x.HasPersonal), (i, total, path) => report.Say(path, i, total));
                }
                if (chosen != null)
                {
                    report.Say("Writing and checking the backup…");
                    OrphanCleanup.WriteBackups(r, plan, chosen);   // throws before anything is changed
                }
                var o = OrphanCleanup.Run(r, plan, profiles, (i, total, path) => report.Say(path, i, total), cancel.Token);
                zipSaved = saved;
                report.Say("Reading the result…");
                foreach (var gone in o.DeletedFolders) gone.Parent?.Children?.Remove(gone);
                foreach (var (folder, _, _) in plan.Leftovers.Where(l => !o.DeletedFolders.Contains(l.Folder)))
                    Scanner.Reprobe(r, folder, resolveNames: false);   // partly deleted or untouched: show what is really there
                foreach (var top in OrphanCleanup.ReprobeRoots(plan)) Scanner.Reprobe(r, top, resolveNames: false);
                foreach (var n in plan.Owners) Scanner.Reprobe(r, n, subtree: false, resolveNames: false);
                Scanner.ResolveNames(r);
                return (Classify(r, kb, report), o);
            }, cancel);

            Apply(done);
            Tabs.SelectedIndex = 2;
            var text = $"{outcome.OwnersChanged:N0} of {Ui.Objects(plan.Owners.Count)} now have Administrators as owner. "
                       + $"{outcome.EntriesChanged:N0} of {Ui.Objects(plan.Entries.Count)} lost their entries for the orphaned SIDs."
                       + (profiles.Count > 0 ? $" {outcome.ProfilesDeleted:N0} of {Ui.Count(profiles.Count, "profile")} deleted." : "")
                       + (plan.Leftovers.Count > 0 ? $" {outcome.FoldersDeleted:N0} of {plan.Leftovers.Count:N0} leftover folders deleted." : "")
                       + (plan.RemoveChosen.Count > 0 ? $" {outcome.FilesDeleted:N0} of {Ui.Count(plan.RemoveChosen.Count, "explained leftover file")} inside Windows deleted." : "")
                       + (outcome.BytesFreed > 0 ? $" {Ui.Size(outcome.BytesFreed)} freed." : "")
                       + (zipFile != null ? $"\n\nPersonal files saved first ({Ui.Count(zipSaved.Files, "file")}, {Ui.Size(zipSaved.Bytes)}, checked):\n{zipFile}" : "")
                       + (plan.Inside.Count + plan.Removable.Count - plan.RemoveChosen.Count > 0 ? $"\n\n{plan.Inside.Count + plan.Removable.Count - plan.RemoveChosen.Count:N0} found under %SystemRoot% were left exactly as they are." : "")
                       + (outcome.Cancelled ? " Stopped before the end — the rest is unchanged." : "")
                       + (outcome.Failed.Count > 0 ? $"\n\n{outcome.Failed.Count:N0} could not be changed:\n"
                          + string.Join("\n", outcome.Failed.Take(8).Select(f => $"  {f.Path} — error {f.Error}: {Classifier.Win32Message(f.Error)}"))
                          + (outcome.Failed.Count > 8 ? $"\n  … and {outcome.Failed.Count - 8:N0} more" : "") : "")
                       + (files.Count > 0
                          ? "\n\nBackup of the removed entries:\n" + string.Join("\n", files.Select(f => f.File))
                            + "\n\nTo restore them, run in an elevated PowerShell:\n" + string.Join("\n", files.Select(f => IcaclsBackup.RestoreCommand(f.Drive, f.File)))
                          : "")
                       + "\n\nOwners cannot be restored: the old accounts no longer exist.";
            SetStatus($"Orphan clean-up: {outcome.OwnersChanged:N0} owners replaced, {outcome.EntriesChanged:N0} objects cleaned, "
                      + $"{outcome.FoldersDeleted:N0} leftover folders deleted ({Ui.Size(outcome.BytesFreed)}).",
                outcome.Failed.Count > 0 || outcome.Cancelled ? "Brush.Warn" : "Brush.Ok");
            HueMessage.Show(this, "Orphan clean-up done", text);
        }
        catch (Exception ex)
        {
            SetStatus("Clean-up failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Orphan clean-up failed", ex.Message
                + (files.Any(f => File.Exists(f.File))
                    ? "\n\nIf anything was changed, the backup is here:\n" + string.Join("\n", files.Select(f => f.File))
                      + "\n\nRestore with:\n" + string.Join("\n", files.Select(f => IcaclsBackup.RestoreCommand(f.Drive, f.File)))
                    : ""));
        }
        finally { EndRunning(); }
    }

    // ================================================================================== explorer grants

    /// <summary>Step 1: preview where it was asked for (Explorer or Accounts & groups). Nothing is written.</summary>
    private void StartGrantUndo(string sid, ScanNode? only, bool fromPrincipal)
    {
        if (!MayAct()) return;
        if (_r == null || _cls == null) return;
        if (ExplorerGrants.WhyNot(_r) is { } why) { SetStatus(why, "Brush.Warn"); return; }
        var plan = ExplorerGrants.Plan(_r, _cls, sid, only);
        if (AskAboutOtherWindows(plan.Folders) is not { } leave) { SetStatus("Undo cancelled — nothing was changed."); return; }
        if (leave.Count > 0) plan = ExplorerGrants.Plan(_r, _cls, sid, only, leave);
        // The preview opens where its button was clicked, so it can never wait unseen on another tab.
        var host = fromPrincipal ? PrincipalDetails
                 : Tabs.SelectedIndex == 1 ? FindingDetails
                 : Tabs.SelectedIndex == 2 ? PrincipalDetails
                 : ExplorerDetails;
        host.Content = DetailsBuilder.GrantPreview(Ctx(), plan, chosen => _ = DoGrantUndo(plan, chosen, host), () =>
        {
            host.Content = null;
            SetStatus("Undo cancelled — nothing was changed.");
        });
        host.ScrollToTop();
    }

    /// <summary>Step 2: backup (asked, written, verified), the change, then re-read and re-classify.</summary>
    private async Task DoGrantUndo(GrantPlan plan, IReadOnlyList<ScanNode> chosen, ScrollViewer host)
    {
        if (_r == null) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save a backup of the entries that change before undoing the Explorer grants",
            Filter = "icacls backup (*.txt)|*.txt|All files (*.*)|*.*",
            FileName = $"AclLegibility-explorer-grants-{DateTime.Now:yyyyMMdd-HHmm}.txt",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
        if (dlg.ShowDialog(this) != true) { SetStatus("Undo cancelled — no backup chosen, nothing was changed."); return; }
        var file = dlg.FileName;
        var files = ExplorerGrants.BackupFiles(chosen, file);
        var r = _r;
        var kb = _kb;
        var name = r.NameOf(plan.Sid).Display;
        using var cancel = new CancellationTokenSource();
        BeginRunning("Undoing Explorer grants", cancelable: true);
        try
        {
            var (done, outcome) = await Busy.RunAsync("Undoing Explorer grants", report =>
            {
                report.Say("Writing and checking the backup…");
                ExplorerGrants.WriteBackups(r, chosen, file);   // throws before anything is changed
                var o = ExplorerGrants.Run(r, plan.Sid, chosen, (i, total, path) => report.Say(path, i, total), cancel.Token);
                report.Say("Reading the result…");
                var set = new HashSet<ScanNode>(chosen);
                foreach (var top in chosen.Where(n => !n.Ancestors().Any(set.Contains)))
                    Scanner.Reprobe(r, top, resolveNames: false);
                return (Classify(r, kb, report), o);
            }, cancel);

            Apply(done);
            var text = $"{name}: {outcome.Changed:N0} of {Ui.Count(chosen.Count, "folder")} "
                       + (outcome.Changed == 1 ? "no longer carries" : "no longer carry") + " the Explorer grant."
                       + (outcome.Cancelled ? " Stopped before the end — the rest is unchanged." : "")
                       + (outcome.Failed.Count > 0 ? $"\n\n{outcome.Failed.Count:N0} could not be changed:\n"
                          + string.Join("\n", outcome.Failed.Take(8).Select(f => $"  {f.Path} — error {f.Error}: {Classifier.Win32Message(f.Error)}")) : "")
                       + "\n\nBackup of the removed entries:\n" + string.Join("\n", files.Select(f => f.File))
                       + "\n\nTo restore them, run in an elevated PowerShell:\n" + string.Join("\n", files.Select(f => IcaclsBackup.RestoreCommand(f.Drive, f.File)));
            SetStatus($"Explorer grants of {name}: {outcome.Changed:N0} removed.", outcome.Failed.Count > 0 || outcome.Cancelled ? "Brush.Warn" : "Brush.Ok");
            host.Content = null;
            HueMessage.Show(this, "Explorer grants undone", text);
        }
        catch (Exception ex)
        {
            SetStatus("Undo failed: " + ex.Message, "Brush.Error");
            HueMessage.Show(this, "Undoing Explorer grants failed", ex.Message
                + (files.Any(f => File.Exists(f.File))
                    ? "\n\nIf anything was changed, the backup is here:\n" + string.Join("\n", files.Select(f => f.File))
                      + "\n\nRestore with:\n" + string.Join("\n", files.Select(f => IcaclsBackup.RestoreCommand(f.Drive, f.File)))
                    : ""));
        }
        finally { EndRunning(); }
    }

    // ================================================================================== copy for AI

    private AiExport Exporter()
    {
        var masker = new Masker(_r!, _ckb!, _settings, MaskCheck.IsChecked == true);
        return new AiExport(_r!, _ckb!, _cls!, masker, _settings.ExportMaxItems);
    }

    private void CopyNodeForAi(ScanNode n)
    {
        if (_r == null) return;
        Deliver(Exporter().Nodes(n.FullPath, new[] { n }), n.Name);
    }

    private void CopySubtreeForAi(ScanNode n)
    {
        if (_r == null) return;
        var nodes = new List<ScanNode> { n };
        var stack = new Stack<ScanNode>();
        if (n.Children != null) for (int i = n.Children.Count - 1; i >= 0; i--) stack.Push(n.Children[i]);
        while (stack.Count > 0)
        {
            var c = stack.Pop();
            if (c.SubtreeAttention == 0) continue;
            if (c.Findings?.Any(f => f.NeedsAttention) == true) nodes.Add(c);
            if (c.Children != null) for (int i = c.Children.Count - 1; i >= 0; i--) stack.Push(c.Children[i]);
        }
        var findings = nodes.SelectMany(x => x.Findings ?? new()).Where(f => f.NeedsAttention || f.Node == n).ToList();
        Deliver(Exporter().Nodes(n.FullPath + " (with findings below)", nodes, findings), n.Name + "-subtree");
    }

    private void CopyPrincipalForAi(string sid)
    {
        if (_r == null || _cls == null) return;
        var refs = _cls.ExplicitRefs.TryGetValue(sid, out var l) ? l : new List<ScanNode>();
        var via = _r.Inventory.GroupsOf(sid)
            .Where(g => g.Sid != null && _cls.ExplicitRefs.ContainsKey(g.Sid))
            .Select(g => (g, (IReadOnlyList<ScanNode>)_cls.ExplicitRefs[g.Sid!]))
            .ToList();
        Deliver(Exporter().Principal(sid, refs, via), "principal");
    }

    private void Deliver(string markdown, string nameHint, bool forceFile = false)
    {
        bool masked = MaskCheck.IsChecked == true;
        if (forceFile)
        {
            var safe = string.Concat(nameHint.Select(ch => System.IO.Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save as Markdown",
                Filter = "Markdown (*.md)|*.md|All files (*.*)|*.*",
                FileName = $"acllegibility-{safe}-{DateTime.Now:yyyyMMdd-HHmm}.md",
            };
            if (dlg.ShowDialog(this) != true) return;
            File.WriteAllText(dlg.FileName, markdown);
            SetStatus($"Saved {markdown.Length:N0} characters to {dlg.FileName}{(masked ? " (names masked)" : "")}.");
            return;
        }
        // Copy for AI always goes to the clipboard, whatever the size; files only via "Save … as Markdown".
        if (SetClipboard(markdown))
            SetStatus($"Copied {Ui.Size(markdown.Length * 2L)} ({markdown.Length:N0} characters) for AI{(masked ? " · names masked" : " · not masked")}.",
                markdown.Length > 400_000 ? "Brush.Warn" : "Brush.Ok");
    }

    private bool SetClipboard(string text)
    {
        for (int i = 0; i < 6; i++)
        {
            try { Clipboard.SetDataObject(text, true); return true; }
            catch (COMException) { Thread.Sleep(60); }
        }
        SetStatus("The clipboard is busy — try again.", "Brush.Warn");
        return false;
    }

    // ================================================================================== snapshots & knowledge

    private async void SaveSnapshot_Click(object sender, RoutedEventArgs e)
    {
        if (_r == null) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save snapshot (contains real, unmasked names)",
            Filter = "AclLegibility snapshot (*.aclsnap)|*.aclsnap",
            FileName = $"{_r.Os.ComputerName}-{_r.ScannedUtc.ToLocalTime():yyyyMMdd-HHmm}.aclsnap",
        };
        if (dlg.ShowDialog(this) != true) return;
        var r = _r;
        var path = dlg.FileName;
        try
        {
            await Busy.RunAsync("Saving snapshot", report => { report.Say(path); SnapshotFile.Save(r, path); });
            SetStatus($"Snapshot saved: {path} ({new FileInfo(path).Length / 1024.0 / 1024.0:0.0} MB).");
        }
        catch (Exception ex) { SetStatus("Saving failed: " + ex.Message, "Brush.Error"); }
    }

    private async void OpenSnapshot_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Open snapshot", Filter = "AclLegibility snapshot (*.aclsnap)|*.aclsnap|All files (*.*)|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        var kb = _kb;
        var path = dlg.FileName;
        try
        {
            var done = await Busy.RunAsync("Opening snapshot", report =>
            {
                report.Say(path);
                var r = SnapshotFile.Load(path);
                return Classify(r, kb, report);
            });
            Apply(done);
            StopPill("Snapshot", "Hue.Pill.Stale");
            var r2 = done.R;
            SetStatus($"Snapshot of {r2.Os.ComputerName} from {r2.ScannedUtc.ToLocalTime():g}: {r2.ObjectCount:N0} objects, " +
                      $"{r2.Findings.Where(f => f.NeedsAttention).Select(f => f.Node).Distinct().Count():N0} need attention."
                      + (r2.LoadNote != null ? " " + r2.LoadNote : ""), r2.LoadNote != null ? "Brush.Warn" : "Brush.Ok");
        }
        catch (Exception ex) { SetStatus("Could not open snapshot: " + ex.Message, "Brush.Error"); }
    }

    /// <summary>Loads an earlier snapshot as the baseline, classifies it with the current knowledge base and lists
    /// only the differences in the Changes tab. The current scan stays what the other tabs show.</summary>
    private async void CompareSnapshot_Click(object sender, RoutedEventArgs e)
    {
        if (_r == null) return;
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Compare with an earlier snapshot (the baseline)", Filter = "AclLegibility snapshot (*.aclsnap)|*.aclsnap|All files (*.*)|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        var kb = _kb;
        var cur = _r;
        var path = dlg.FileName;
        try
        {
            var diff = await Busy.RunAsync("Comparing with snapshot", report =>
            {
                report.Say(path);
                var b = SnapshotFile.Load(path);
                Classify(b, kb, report);
                return SnapshotDiff.Compute(path, b, cur, s => report.Say(s));
            });
            ChangesView.Content = DetailsBuilder.Changes(Ctx(), diff);
            ChangesTab.Visibility = Visibility.Visible;
            ChangesTab.IsSelected = true;
            SetStatus($"Compared with snapshot from {diff.BaselineUtc.ToLocalTime():g}: {Ui.Count(diff.NewFindings.Count, "new finding")}, "
                      + $"{Ui.Objects(diff.Changed.Count)} with changed security, {Ui.Objects(diff.Added.Count)} added, {Ui.Objects(diff.Removed.Count)} removed.");
        }
        catch (Exception ex) { SetStatus("Could not compare: " + ex.Message, "Brush.Error"); }
    }

    private async void ReloadKb_Click(object sender, RoutedEventArgs e)
    {
        _kb = LoadKnowledge();
        UpdateKbCaption();
        if (_r != null)
        {
            var r = _r;
            var kb = _kb;
            try
            {
                var done = await Busy.RunAsync("Re-classifying with the reloaded knowledge base", report => Classify(r, kb, report));
                Apply(done);
            }
            catch (Exception ex) { SetStatus("Re-classifying failed: " + ex.Message, "Brush.Error"); return; }
        }
        else BuildKnowledgePage();
        SetStatus("Knowledge base reloaded. " + string.Join(" ", _kb.LoadMessages),
            _kb.LoadMessages.Any(m => m.StartsWith("Could not")) ? "Brush.Warn" : "Brush.Ok");
    }

    private void OpenAppFolder_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), $"\"{AppSettings.AppFolder.TrimEnd('\\')}\"") { UseShellExecute = true }); }
        catch (Exception ex) { SetStatus(ex.Message, "Brush.Error"); }
    }

    // ---- knowledge page -----------------------------------------------------------------------

    private void BuildKnowledgePage()
    {
        var p = new StackPanel { MaxWidth = 1100, HorizontalAlignment = HorizontalAlignment.Left };
        Style St(string key) => (Style)FindResource(key);
        TextBlock Body(string s) { var t = new TextBlock { Text = s, Style = St("Text.Body"), Margin = new Thickness(0, 0, 0, 6) }; t.SetResourceReference(TextBlock.ForegroundProperty, "Brush.Text"); return t; }
        TextBlock Dim(string s) => new() { Text = s, Style = St("Text.Body"), Margin = new Thickness(0, 0, 0, 6) };
        TextBlock Cap(string s) => new() { Text = s, Style = St("Text.Caption"), Margin = new Thickness(0, 0, 0, 6) };
        TextBlock Sec(string s) => new() { Text = s.ToUpperInvariant(), Style = St("Text.Section"), Margin = new Thickness(0, 22, 0, 8) };

        var d = _kb.Doc;
        p.Children.Add(new TextBlock { Text = $"Knowledge base v{d.Version}", Style = St("Text.Heading"), Margin = new Thickness(0, 0, 0, 6) });
        if (d.Description != null) p.Children.Add(Dim(d.Description));
        p.Children.Add(Body($"{d.Principals.Count} principals · {d.Paths.Count} locations · {d.Patterns.Count} patterns · {d.Quirks.Count} quirk rules · " +
                            $"{d.Streams.Count} streams · {d.ReparseTags.Count} reparse tags · {d.ReparsePoints.Count} reparse points · {d.Shares.Count} shares · {d.Accounts.Count} accounts"));

        p.Children.Add(Sec("What the origins mean"));
        foreach (var (o, text) in new[]
        {
            (Origin.Modified, "A known Windows object that differs from what the knowledge base expects in a way that gives someone more control (write, delete, ownership, permission changes, removed protection), or a stock link that points elsewhere. The differences are listed."),
            (Origin.Custom, "Configuration made after setup by an administrator, an installer or an application: non-Windows accounts, app pool identities, orphaned SIDs."),
            (Origin.Unknown, "Cannot be told apart yet. These are the gaps: copy them for AI and feed the answer back."),
            (Origin.PerAccount, "Windows' own layout for one account that exists: a profile, a policy record, a scheduled task or a log of that account. Windows created it and gave the account its access; what is inside may reflect that account's settings."),
            (Origin.Differs, "A known Windows object that differs from the fresh reference install only in ways that give no one more control: read or list rights, or which system account (SYSTEM, Administrators, TrustedInstaller) holds a right or owns it. Another Windows build or an update usually wrote it; who did is not recorded by Windows."),
            (Origin.Trace, "A leftover of normal use rather than configuration: download marks, object IDs, hard links outside Windows, sync metadata."),
            (Origin.Stock, "Shipped or set by Windows setup or servicing."),
        })
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var tag = new ContentControl { Style = Ui.TagStyle(o), Content = OriginText.Label(o), Width = 130, VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(tag, Dock.Left);
            row.Children.Add(tag);
            row.Children.Add(Body(text));
            p.Children.Add(row);
        }
        p.Children.Add(Cap("Only Modified, Custom and Unknown count as needing attention. Confidence: documented = Microsoft documentation · observed = confirmed on a real install · assumed = from experience, not yet confirmed · unverified = location recognised, ACL not compared."));

        if (_r != null && _r.Findings.Count > 0)
        {
            p.Children.Add(Sec("This scan: findings by kind and origin"));
            p.Children.Add(CategoryOriginTable());
            p.Children.Add(Cap($"{_r.Findings.Count(f => f.KbId != null):N0} of {_r.Findings.Count:N0} findings matched a knowledge entry. "
                               + $"{_r.Findings.Where(f => f.NeedsAttention).Select(f => f.Node).Distinct().Count():N0} objects need attention."));
            p.Children.Add(Sec("This scan"));
            p.Children.Add(Body($"OS: {_r.Os.VersionLine}"));
            p.Children.Add(Body($"Knowledge target: {(_r.Os.IsTestedTarget ? _r.Os.TargetKey : "untested — closest family " + _r.Os.FamilyKey)}"));
            p.Children.Add(Body($"Privileges enabled: {string.Join(", ", _r.PrivilegesEnabled.DefaultIfEmpty("none"))}"));
            if (_r.Cancelled) p.Children.Add(Dim("The scan was cancelled: the tree is partial, so nothing is listed as not present."));
            foreach (var note in _r.Inventory.Notes) p.Children.Add(Dim(note));
            AddNotPresent(p, Sec, Dim, Cap);
        }

        p.Children.Add(Sec("Your additions"));
        var userPath = AppSettings.UserKnowledgePath;
        p.Children.Add(Body(File.Exists(userPath) ? $"{userPath} — {_kb.UserEntryCount} entries loaded." : $"{userPath} does not exist yet."));
        foreach (var m in _kb.LoadMessages) p.Children.Add(Dim(m));
        if (_ckb != null) foreach (var prob in _ckb.Problems) p.Children.Add(Dim("Problem: " + prob));
        p.Children.Add(Cap("Entries with the same id replace built-in ones; \"remove\": true deletes one. After editing, press “Reload knowledge” — the current scan is re-classified without rescanning."));
        var create = new Button { Content = "Create knowledge.user.json template", IsEnabled = !File.Exists(userPath), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
        create.Click += (_, _) =>
        {
            try { File.WriteAllText(userPath, UserTemplate); SetStatus("Created " + userPath); create.IsEnabled = false; }
            catch (Exception ex) { SetStatus("Could not create the file: " + ex.Message, "Brush.Error"); }
        };
        p.Children.Add(create);
        KnowledgeInfo.Content = p;
    }

    /// <summary>Stock items and compatibility links a standard install of this Windows creates that are not in this scan.
    /// Listed apart and never judged: an image built with fewer components, or a deliberate clean-up, leaves them out.</summary>
    private void AddNotPresent(StackPanel p, Func<string, TextBlock> sec, Func<string, TextBlock> dim, Func<string, TextBlock> cap)
    {
        if (_r == null || _r.Cancelled) return;
        p.Children.Add(sec("Not present in this scan"));
        if (_r.NotPresent.Count == 0 && _r.NotPresentUnlisted.Count == 0)
        {
            p.Children.Add(dim("Everything the knowledge base expects on the scanned volumes is there. Volumes are only checked when they were scanned from their root."));
            return;
        }
        p.Children.Add(dim("What a standard install of this Windows creates and this scan does not contain. Not a judgement: images "
                           + "built with fewer components and deliberate clean-ups leave these out. Volumes are only checked when they "
                           + "were scanned from their root."));
        foreach (var folder in _r.NotPresent.GroupBy(x => x.Folder, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            var head = new TextBlock { Text = folder.Key, Style = (Style)FindResource("Text.Body"), Margin = new Thickness(0, 10, 0, 4) };
            head.SetResourceReference(TextBlock.ForegroundProperty, "Brush.Text");
            p.Children.Add(head);
            foreach (var item in folder.OrderBy(x => x.Path, StringComparer.OrdinalIgnoreCase))
            {
                var name = item.Path[(item.Path.TrimEnd('\\').LastIndexOf('\\') + 1)..];
                var line = new WrapPanel { Margin = new Thickness(16, 0, 0, 2) };
                var label = new TextBlock
                {
                    Text = name + (item.IsLink ? "  ·  link" + (item.Target != null ? " → " + item.Target : "") : "  ·  item"),
                    FontFamily = (FontFamily)FindResource("Font.Mono"), FontSize = 12, VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 12, 0),
                };
                label.SetResourceReference(TextBlock.ForegroundProperty, "Brush.TextDim");
                line.Children.Add(label);
                var explain = cap((item.Explain ?? "No explanation in the knowledge base.") + "  (knowledge entry: " + item.KbId + ")");
                explain.TextWrapping = TextWrapping.Wrap;
                explain.Margin = new Thickness(16, 0, 0, 6);
                explain.Visibility = Visibility.Collapsed;
                var toggle = new Button { Content = "What it is", Style = (Style)FindResource("Hue.Button.Ghost"), Padding = new Thickness(8, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center };
                toggle.Click += (_, _) => explain.Visibility = explain.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
                line.Children.Add(toggle);
                p.Children.Add(line);
                p.Children.Add(explain);
            }
        }
        foreach (var folder in _r.NotPresentUnlisted.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            p.Children.Add(cap($"{folder}: its contents could not be listed, so nothing below it is said to be absent."));
    }

    private Grid CategoryOriginTable()
    {
        var origins = FilterOrigins;
        var g = new Grid { HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 8) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(190) });
        foreach (var _ in origins) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(130) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });

        void Cell(int row, int col, UIElement e, bool right = false)
        {
            if (e is FrameworkElement fe) { fe.Margin = new Thickness(8, 5, 8, 5); fe.HorizontalAlignment = right ? HorizontalAlignment.Right : HorizontalAlignment.Left; }
            Grid.SetRow(e, row); Grid.SetColumn(e, col);
            g.Children.Add(e);
        }
        TextBlock Num(int n, bool strong)
        {
            var t = new TextBlock { Text = n == 0 ? "–" : n.ToString("N0"), FontFamily = (FontFamily)FindResource("Font.Mono"), FontSize = 12 };
            t.SetResourceReference(TextBlock.ForegroundProperty, strong && n > 0 ? "Brush.Text" : "Brush.TextMuted");
            return t;
        }

        g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var head = new Border();
        head.SetResourceReference(Border.BackgroundProperty, "Brush.Raised");
        Grid.SetColumnSpan(head, origins.Length + 2);
        g.Children.Add(head);
        Cell(0, 0, new TextBlock { Text = "KIND", Style = (Style)FindResource("Text.Section") });
        for (int i = 0; i < origins.Length; i++)
            Cell(0, i + 1, new ContentControl { Style = Ui.TagStyle(origins[i]), Content = OriginText.Label(origins[i]) });
        Cell(0, origins.Length + 1, new TextBlock { Text = "TOTAL", Style = (Style)FindResource("Text.Section") }, right: true);

        var counts = _r!.Findings.GroupBy(f => (f.Category, f.Origin)).ToDictionary(x => x.Key, x => x.Count());
        int row = 1;
        foreach (var cat in Enum.GetValues<FindingCategory>())
        {
            int total = origins.Sum(o => counts.GetValueOrDefault((cat, o)));
            if (total == 0) continue;
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var line = new Border { BorderThickness = new Thickness(0, 0, 0, 1) };
            line.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");
            Grid.SetRow(line, row); Grid.SetColumnSpan(line, origins.Length + 2);
            g.Children.Add(line);
            var name = new TextBlock { Text = OriginText.Label(cat) };
            name.SetResourceReference(TextBlock.ForegroundProperty, "Brush.Text");
            Cell(row, 0, name);
            for (int i = 0; i < origins.Length; i++)
                Cell(row, i + 1, Num(counts.GetValueOrDefault((cat, origins[i])), origins[i] is Origin.Modified or Origin.Custom or Origin.Unknown), right: true);
            Cell(row, origins.Length + 1, Num(total, true), right: true);
            row++;
        }
        return g;
    }

    private const string UserTemplate = """
{
  // Your own knowledge entries. Merged over the built-in knowledge base:
  // same "id" replaces a built-in entry, "remove": true deletes it.
  // Paste entries returned by an AI here, then press "Reload knowledge".
  "paths": [
  ],
  "patterns": [
  ],
  "streams": [
  ],
  "reparsePoints": [
  ],
  "quirks": [
  ],
  "principals": [
  ],
  "shares": [
  ],
  "accounts": [
  ]
}
""";
}
