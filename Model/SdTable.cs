using System;
using System.Collections.Generic;
using System.Linq;
namespace AclLegibility.Model;

/// <summary>
/// De-duplicated security descriptors. NTFS itself shares descriptors between objects,
/// so a full volume typically has only a few thousand distinct ones.
/// </summary>
public sealed class SdTable
{
    private readonly Dictionary<byte[], int> _index = new(ByteArrayComparer.Instance);
    private readonly List<byte[]> _items = new();
    private readonly object _lock = new();

    public int Count { get { lock (_lock) return _items.Count; } }

    public byte[] this[int i] { get { lock (_lock) return _items[i]; } }

    public int Add(ReadOnlySpan<byte> sd)
    {
        var copy = sd.ToArray();
        lock (_lock)
        {
            if (_index.TryGetValue(copy, out var i)) return i;
            i = _items.Count;
            _items.Add(copy);
            _index[copy] = i;
            return i;
        }
    }

    /// <summary>Adds an already-owned array (used when loading snapshots).</summary>
    public int AddOwned(byte[] sd)
    {
        lock (_lock)
        {
            if (_index.TryGetValue(sd, out var i)) return i;
            i = _items.Count;
            _items.Add(sd);
            _index[sd] = i;
            return i;
        }
    }

    public IReadOnlyList<byte[]> Snapshot() { lock (_lock) return _items.ToArray(); }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public bool Equals(byte[]? x, byte[]? y) => x != null && y != null && x.AsSpan().SequenceEqual(y);
        public int GetHashCode(byte[] obj)
        {
            var h = new HashCode();
            h.AddBytes(obj);
            return h.ToHashCode();
        }
    }
}
