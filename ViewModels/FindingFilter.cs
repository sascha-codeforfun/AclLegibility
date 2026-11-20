using System;
using System.Collections.Generic;
using System.Linq;
using AclLegibility.Model;

namespace AclLegibility.ViewModels;

/// <summary>The rows of filter pills in the Findings tab: origin, kind and unreadable cause.</summary>
public enum PillRow { Origin, Kind, Cause }

/// <summary>
/// The Findings filter. Within a row, lit pills are alternatives (none lit = all); the rows combine. One rule on top: a pill
/// that is clicked on while nothing it stands for lies inside the current selection clears the other rows — otherwise
/// clicking "Unreadable 4" under the pre-selected Custom + Unknown would show an empty list.
/// </summary>
public static class FindingFilter
{
    public static bool Lets(IReadOnlyList<(string Key, bool Lit)> row, string key)
    {
        bool anyLit = false;
        foreach (var (k, lit) in row)
        {
            if (!lit) continue;
            anyLit = true;
            if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return !anyLit;
    }

    public static bool Passes(FindingRowVm r, IReadOnlyList<(string Key, bool Lit)> origins, IReadOnlyList<(string Key, bool Lit)> kinds,
        IReadOnlyList<(string Key, bool Lit)> causes, string text)
    {
        var f = r.Finding;
        // A lit "Link" pill shows every link, stock ones included, whatever the origin pills say.
        bool allLinks = f.Category == FindingCategory.Link && kinds.Any(c => c.Lit && c.Key == nameof(FindingCategory.Link));
        return (allLinks || Lets(origins, f.Origin.ToString()))
               && Lets(kinds, f.Category.ToString())
               && (f.Cause is not { } cause || Lets(causes, cause.ToString()))
               && (text.Length == 0 || r.Path.Contains(text, StringComparison.OrdinalIgnoreCase)
                   || r.Summary.Contains(text, StringComparison.OrdinalIgnoreCase)
                   || (f.KbId?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false));
    }

    /// <summary>The key a finding has in one row of pills (null: the row does not apply to it).</summary>
    public static string? KeyIn(Finding f, PillRow row) => row switch
    {
        PillRow.Origin => f.Origin.ToString(),
        PillRow.Kind => f.Category.ToString(),
        _ => f.Cause?.ToString(),
    };

    /// <summary>True when no finding with <paramref name="key"/> in <paramref name="row"/> passes the pills as they are now
    /// (the text search is left out: it is not a pill row). Then the other rows are cleared.</summary>
    public static bool NothingInside(IEnumerable<FindingRowVm> rows, PillRow row, string key,
        IReadOnlyList<(string Key, bool Lit)> origins, IReadOnlyList<(string Key, bool Lit)> kinds, IReadOnlyList<(string Key, bool Lit)> causes) =>
        !rows.Any(r => string.Equals(KeyIn(r.Finding, row), key, StringComparison.OrdinalIgnoreCase)
                       && Passes(r, origins, kinds, causes, ""));
}
