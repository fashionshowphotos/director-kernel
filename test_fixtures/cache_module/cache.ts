/**
 * Cache Module - In-memory cache with TTL and eviction
 */

export interface CacheConfig {
  defaultTtlMs: number;
  maxEntries: number;
  cleanupIntervalMs: number;
}

export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  accessCount: number;
  lastAccessedAt: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
}

export type CacheError = 'KEY_NOT_FOUND' | 'CACHE_FULL' | 'INVALID_TTL';

export class Cache<T> {
  private store: Map<string, CacheEntry<T>> = new Map();
  private stats: CacheStats = { hits: 0, misses: 0, evictions: 0, size: 0 };
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(private config: CacheConfig) {
    if (config.defaultTtlMs <= 0) {
      throw new Error('CACHE_CONFIG_INVALID: defaultTtlMs must be positive');
    }
    this.startCleanup();
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    
    if (!entry) {
      this.stats.misses++;
      return undefined;
    }

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      this.stats.size--;
      this.stats.misses++;
      return undefined;
    }

    entry.accessCount++;
    entry.lastAccessedAt = Date.now();
    this.stats.hits++;
    return entry.value;
  }

  set(key: string, value: T, ttlMs?: number): boolean {
    const effectiveTtl = ttlMs ?? this.config.defaultTtlMs;
    
    if (effectiveTtl <= 0) {
      return false;
    }

    if (!this.store.has(key) && this.store.size >= this.config.maxEntries) {
      this.evictLRU();
    }

    const entry: CacheEntry<T> = {
      value,
      expiresAt: Date.now() + effectiveTtl,
      accessCount: 0,
      lastAccessedAt: Date.now(),
    };

    const isNew = !this.store.has(key);
    this.store.set(key, entry);
    
    if (isNew) {
      this.stats.size++;
    }

    return true;
  }

  delete(key: string): boolean {
    const existed = this.store.delete(key);
    if (existed) {
      this.stats.size--;
    }
    return existed;
  }

  clear(): void {
    this.store.clear();
    this.stats.size = 0;
  }

  getStats(): CacheStats {
    return { ...this.stats };
  }

  close(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.store) {
      if (entry.lastAccessedAt < oldestTime) {
        oldestTime = entry.lastAccessedAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.store.delete(oldestKey);
      this.stats.size--;
      this.stats.evictions++;
    }
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store) {
        if (now > entry.expiresAt) {
          this.store.delete(key);
          this.stats.size--;
        }
      }
    }, this.config.cleanupIntervalMs);
  }
}
