using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityAudit.Services;

public class LruCache<TKey, TValue> where TKey : notnull
{
    private readonly int _maxSize;
    private readonly Dictionary<TKey, LinkedListNode<CacheItem>> _cache = new();
    private readonly LinkedList<CacheItem> _lru = new();
    private readonly object _lock = new();

    public LruCache(int maxSize)
    {
        if (maxSize <= 0)
            throw new ArgumentException("Cache size must be positive", nameof(maxSize));
        _maxSize = maxSize;
    }

    public bool TryGet(TKey key, out TValue value)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var node))
            {
                _lru.Remove(node);
                _lru.AddFirst(node);
                value = node.Value.Value;
                return true;
            }
            value = default!;
            return false;
        }
    }

    public void Set(TKey key, TValue value)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var node))
            {
                _lru.Remove(node);
                node.Value.Value = value;
                _lru.AddFirst(node);
            }
            else
            {
                if (_cache.Count >= _maxSize)
                {
                    var oldest = _lru.Last!;
                    _cache.Remove(oldest.Value.Key);
                    _lru.RemoveLast();
                }

                var newNode = _lru.AddFirst(new CacheItem(key, value));
                _cache[key] = newNode;
            }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _cache.Clear();
            _lru.Clear();
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _cache.Count;
            }
        }
    }

    private class CacheItem
    {
        public TKey Key { get; }
        public TValue Value { get; set; }

        public CacheItem(TKey key, TValue value)
        {
            Key = key;
            Value = value;
        }
    }
}
