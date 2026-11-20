using System;
using System.Collections.Generic;
using System.Linq;
using AclLegibility.Model;

namespace AclLegibility.Security;

/// <summary>Where an inherited entry came from, and an approximate effective-access evaluation.</summary>
public static class AccessAnalysis
{
    /// <summary>Nearest ancestor holding an explicit, inheritable entry for the same principal and type.</summary>
    public static ScanNode? InheritedFrom(ScanResult r, ScanNode node, AceInfo ace)
    {
        if (!ace.IsInherited) return null;
        foreach (var anc in node.Ancestors())
        {
            var sd = r.SdOf(anc);
            if (sd == null) continue;
            var list = ace.IsAudit ? sd.Sacl : sd.Dacl;
            if (list == null) continue;
            foreach (var a in list)
            {
                if (a.IsInherited || a.Type != ace.Type) continue;
                if ((a.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) == 0) continue;
                if (string.Equals(a.Sid, ace.Sid, StringComparison.OrdinalIgnoreCase)) return anc;
                // CREATOR OWNER / CREATOR GROUP entries turn into the creator's SID on children
                if (a.Sid is "S-1-3-0" or "S-1-3-1") return anc;
            }
            if (sd.DaclProtected && !ace.IsAudit) return null;
        }
        return null;
    }

    public sealed record Contribution(AceInfo Ace, bool Denies, uint Bits, string? Note);

    public sealed class Result
    {
        public uint Granted;
        public uint Denied;
        public List<Contribution> Contributions { get; } = new();
        public List<string> TokenSids { get; } = new();
        public bool NullDacl;
        public bool OwnerImplicit;
    }

    /// <summary>The SIDs a token of this principal would carry, as far as can be told from local data.</summary>
    public static List<string> TokenFor(ScanResult r, string sid)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { sid };
        var use = r.NameOf(sid).Use;
        bool isAccount = use is SidUse.User or SidUse.Computer
                         || sid.StartsWith("S-1-5-82-", StringComparison.Ordinal)
                         || sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)
                         || sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20" or "S-1-5-17";
        if (isAccount)
        {
            set.Add("S-1-1-0");        // Everyone
            set.Add("S-1-5-11");       // Authenticated Users
            if (use == SidUse.User)
            {
                set.Add("S-1-5-4");    // INTERACTIVE (assumed logon type)
                set.Add("S-1-2-0");    // LOCAL
                if (r.Os.MachineSid != null && sid.StartsWith(r.Os.MachineSid + "-", StringComparison.OrdinalIgnoreCase))
                    set.Add("S-1-5-113");
            }
            if (sid.StartsWith("S-1-5-82-", StringComparison.Ordinal)) { set.Add("S-1-5-6"); set.Add("S-1-5-32-568"); }
            if (sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)) set.Add("S-1-5-6");
            if (sid == "S-1-5-18") set.Add("S-1-5-32-544");
        }
        // expand local group memberships to a fixed point (Users contains Authenticated Users, etc.)
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var g in r.Inventory.Groups)
            {
                if (g.Sid == null || set.Contains(g.Sid)) continue;
                if (g.Members.Any(m => set.Contains(m.Sid))) { set.Add(g.Sid); changed = true; }
            }
        }
        return set.ToList();
    }

    public static Result Evaluate(SdInfo sd, IReadOnlyCollection<string> token)
    {
        var res = new Result();
        res.TokenSids.AddRange(token);
        var tok = new HashSet<string>(token, StringComparer.OrdinalIgnoreCase);
        if (sd.NullDacl) { res.NullDacl = true; res.Granted = Rights.FILE_ALL_ACCESS; return res; }
        if (sd.Dacl == null) return res;

        bool isOwner = sd.Owner != null && tok.Contains(sd.Owner);
        bool hasOwnerRights = sd.Dacl.Any(a => a.Sid == "S-1-3-4" && !a.IsInheritOnly);
        if (isOwner) tok.Add("S-1-3-4");

        foreach (var a in sd.Dacl)
        {
            if (a.IsInheritOnly || !(a.IsAllow || a.IsDeny)) continue;
            if (!tok.Contains(a.Sid)) continue;
            uint m = a.NormalizedMask & Rights.FILE_ALL_ACCESS;
            if (a.HasCondition)
            {
                res.Contributions.Add(new Contribution(a, a.IsDeny, 0, "conditional entry — not evaluated"));
                continue;
            }
            if (a.IsDeny)
            {
                uint newly = m & ~res.Granted & ~res.Denied;
                res.Denied |= newly;
                if (newly != 0) res.Contributions.Add(new Contribution(a, true, newly, null));
            }
            else
            {
                uint newly = m & ~res.Denied & ~res.Granted;
                res.Granted |= newly;
                if (newly != 0) res.Contributions.Add(new Contribution(a, false, newly, null));
            }
        }
        if (isOwner && !hasOwnerRights)
        {
            const uint implicitOwner = 0x00020000 | 0x00040000; // READ_CONTROL | WRITE_DAC
            uint newly = implicitOwner & ~res.Denied & ~res.Granted;
            if (newly != 0) { res.Granted |= newly; res.OwnerImplicit = true; }
        }
        return res;
    }
}
