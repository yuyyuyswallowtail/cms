# STEP 4: Redis Caching Strategy

## Enterprise CMS Company Profile - Cache Architecture

---

## 1. CACHE KEY STRUCTURE CONVENTION

### 1.1 Key Naming Convention

```
{prefix}:{entity}:{identifier}:{field}
```

| Prefix | Entity | Examples |
|--------|--------|----------|
| `session` | Session data | `session:abc123` |
| `cart` | Shopping cart | `cart:user123` |
| `product` | Products | `product:list:1:10:active`, `product:slug:iphone-15` |
| `user` | User data | `user:id:123`, `user:email:test@test.com` |
| `dashboard` | Dashboard | `dashboard:summary:admin` |
| `search` | Search results | `search:query:iphone:category:electronics` |
| `otp` | OTP codes | `otp:email:test@test.com` |
| `rate` | Rate limiting | `rate:ip:192.168.1.1:/api/login` |
| `report` | Reports | `report:daily:2024-01-01` |
| `notification` | Notifications | `notification:unread:user123` |

### 1.2 Key Patterns

```typescript
// lib/cache/keys.ts
export const cacheKeys = {
  // Session
  session: (token: string) => `session:${token}`,
  sessionUser: (userId: string, token: string) => `session-user:${userId}:${token}`,
  
  // Cart
  cart: (userId: string) => `cart:${userId}`,
  
  // Products
  product: {
    byId: (id: string) => `product:${id}`,
    bySlug: (slug: string) => `product:slug:${slug}`,
    list: (page: number, limit: number, filters?: string) => 
      `product:list:${page}:${limit}${filters ? `:${filters}` : ''}`,
    featured: () => `product:featured`,
    byCategory: (categoryId: string, page: number, limit: number) =>
      `product:category:${categoryId}:${page}:${limit}`,
    search: (query: string, filters?: string) =>
      `search:product:${query}${filters ? `:${filters}` : ''}`,
  },
  
  // Dashboard
  dashboard: {
    summary: (role: string) => `dashboard:summary:${role}`,
    stats: (type: string) => `dashboard:stats:${type}`,
  },
  
  // User
  user: {
    byId: (id: string) => `user:${id}`,
    byEmail: (email: string) => `user:email:${email}`,
    profile: (id: string) => `user:profile:${id}`,
  },
  
  // OTP & Rate Limit
  otp: (email: string) => `otp:${email}`,
  passwordReset: (token: string) => `password-reset:${token}`,
  emailChange: (userId: string) => `email-change:${userId}`,
  rateLimit: (identifier: string, endpoint: string) => `rate:${identifier}:${endpoint}`,
  
  // Notifications
  notifications: {
    unread: (userId: string) => `notification:unread:${userId}`,
    list: (userId: string, page: number) => `notification:list:${userId}:${page}`,
  },
  
  // Reports
  report: {
    daily: (date: string) => `report:daily:${date}`,
    monthly: (year: number, month: number) => `report:monthly:${year}:${month}`,
  },
}
```

---

## 2. TTL STRATEGY

### 2.1 TTL by Data Type

| Data Type | TTL | Reason |
|-----------|-----|--------|
| Sessions | 24h (86400s) | Balance security vs UX |
| Cart | 24h (86400s) | Persist between visits |
| Product Catalog | 1h (3600s) | Frequently updated |
| Featured Products | 15min (900s) | High traffic, low update |
| Dashboard Summary | 5min (300s) | Real-time enough for admin |
| User Profile | 30min (1800s) | Infrequent updates |
| Search Results | 30min (1800s) | Expensive to compute |
| OTP | 5min (300s) | Security |
| Rate Limit | 1min (60s) | Dynamic |
| Reports | 24h (86400s) | Computed daily |

### 2.2 TTL Configuration

```typescript
// lib/cache/ttl.ts
export const TTL = {
  // Auth
  SESSION: 86400,        // 24 hours
  OTP: 300,              // 5 minutes
  PASSWORD_RESET: 3600,  // 1 hour
  EMAIL_CHANGE: 600,     // 10 minutes
  
  // Cart
  CART: 86400,           // 24 hours
  
  // Products
  PRODUCT: 3600,         // 1 hour
  PRODUCT_FEATURED: 900, // 15 minutes
  PRODUCT_LIST: 1800,    // 30 minutes
  PRODUCT_SEARCH: 1800,  // 30 minutes
  
  // Dashboard
  DASHBOARD_SUMMARY: 300, // 5 minutes
  DASHBOARD_STATS: 300,   // 5 minutes
  
  // User
  USER_PROFILE: 1800,    // 30 minutes
  
  // Reports
  REPORT_DAILY: 86400,  // 24 hours
  REPORT_MONTHLY: 86400, // 24 hours
  
  // Notifications
  NOTIFICATION_UNREAD: 60, // 1 minute
  NOTIFICATION_LIST: 60,   // 1 minute
  
  // Rate Limit
  RATE_LIMIT: 60,        // 1 minute
} as const
```

---

## 3. INVALIDATION STRATEGY

### 3.1 Invalidation Patterns

```typescript
// lib/cache/invalidation.ts
import { cacheKeys } from './keys'
import { redis } from '@/lib/redis'
import { TTL } from './ttl'

export class CacheInvalidator {
  // ==================== PRODUCT INVALIDATION ====================
  
  static async invalidateProduct(productId: string) {
    const pipeline = redis.pipeline()
    
    // Delete specific product
    pipeline.del(cacheKeys.product.byId(productId))
    
    // Delete from featured cache
    pipeline.del(cacheKeys.product.featured())
    
    // Note: List caches are pattern-deleted
    // In production, consider using cache tags
    
    await pipeline.exec()
  }
  
  static async invalidateProductList() {
    // Delete all product list caches
    const keys = await redis.keys('product:list:*')
    if (keys.length > 0) {
      await redis.del(...keys)
    }
  }
  
  static async invalidateProductCategory(categoryId: string) {
    const keys = await redis.keys(`product:category:${categoryId}:*`)
    if (keys.length > 0) {
      await redis.del(...keys)
    }
  }
  
  static async invalidateAllProducts() {
    const keys = await redis.keys('product:*')
    if (keys.length > 0) {
      await redis.del(...keys)
    }
  }
  
  // ==================== CART INVALIDATION ====================
  
  static async invalidateCart(userId: string) {
    await redis.del(cacheKeys.cart(userId))
  }
  
  // ==================== USER INVALIDATION ====================
  
  static async invalidateUser(userId: string) {
    const pipeline = redis.pipeline()
    
    pipeline.del(cacheKeys.user.byId(userId))
    pipeline.del(cacheKeys.user.profile(userId))
    
    // Invalidate session (force re-login)
    const sessionKeys = await redis.keys(`session-user:${userId}:*`)
    for (const key of sessionKeys) {
      const token = key.split(':')[2]
      pipeline.del(`session:${token}`)
      pipeline.del(key)
    }
    
    await pipeline.exec()
  }
  
  // ==================== DASHBOARD INVALIDATION ====================
  
  static async invalidateDashboard(role?: string) {
    if (role) {
      await redis.del(cacheKeys.dashboard.summary(role))
    } else {
      const keys = await redis.keys('dashboard:*')
      if (keys.length > 0) {
        await redis.del(...keys)
      }
    }
  }
  
  // ==================== SEARCH INVALIDATION ====================
  
  static async invalidateSearch() {
    const keys = await redis.keys('search:*')
    if (keys.length > 0) {
      await redis.del(...keys)
    }
  }
  
  // ==================== REPORT INVALIDATION ====================
  
  static async invalidateReports(type: 'daily' | 'monthly', date?: string) {
    if (type === 'daily' && date) {
      await redis.del(cacheKeys.report.daily(date))
    } else {
      const keys = await redis.keys('report:*')
      if (keys.length > 0) {
        await redis.del(...keys)
      }
    }
  }
}
```

### 3.2 Cache-Aside Pattern

```typescript
// lib/cache/cache-aside.ts
import { redis } from '@/lib/redis'
import { TTL } from './ttl'

export async function cacheAside<T>(
  key: string,
  fetcher: () => Promise<T>,
  ttl: number = TTL.PRODUCT
): Promise<T> {
  // 1. Try to get from cache
  const cached = await redis.get(key)
  
  if (cached) {
    return JSON.parse(cached) as T
  }
  
  // 2. Cache miss - fetch from source
  const data = await fetcher()
  
  // 3. Store in cache
  if (data !== null && data !== undefined) {
    await redis.setex(key, ttl, JSON.stringify(data))
  }
  
  return data
}

// Usage example
async function getProduct(id: string) {
  return cacheAside(
    `product:${id}`,
    () => db.product.findUnique({ where: { id } }),
    TTL.PRODUCT
  )
}

async function getProductList(page: number, limit: number) {
  const filters = JSON.stringify({ status: 'ACTIVE' })
  return cacheAside(
    `product:list:${page}:${limit}:${filters}`,
    () => db.product.findMany({
      where: { status: 'ACTIVE' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    TTL.PRODUCT_LIST
  )
}
```

---

## 4. REDIS UTILITY CONFIGURATION

### 4.1 Redis Client Setup

```typescript
// lib/redis.ts
import Redis from 'ioredis'

// Singleton Redis client
function createRedisClient() {
  const client = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      const delay = Math.min(times * 50, 2000)
      return delay
    },
    lazyConnect: true,
    enableOfflineQueue: true,
  })
  
  client.on('error', (err) => {
    console.error('Redis connection error:', err)
  })
  
  client.on('connect', () => {
    console.log('Redis connected')
  })
  
  return client
}

// Export singleton instance
export const redis = createRedisClient()

// Helper for pipeline operations
export async function redisPipeline(commands: Array<[string, ...any[]]>) {
  const pipeline = redis.pipeline()
  
  for (const [command, ...args] of commands) {
    pipeline.call(command, ...args)
  }
  
  return pipeline.exec()
}

// Redis connection check
export async function checkRedisConnection(): Promise<boolean> {
  try {
    await redis.ping()
    return true
  } catch {
    return false
  }
}
```

### 4.2 Cache Service

```typescript
// services/cache.service.ts
import { redis } from '@/lib/redis'
import { TTL } from '@/lib/cache/ttl'

export class CacheService {
  // ==================== BASIC OPERATIONS ====================
  
  static async get<T>(key: string): Promise<T | null> {
    const data = await redis.get(key)
    return data ? JSON.parse(data) : null
  }
  
  static async set<T>(key: string, data: T, ttl?: number): Promise<void> {
    await redis.setex(key, ttl || TTL.PRODUCT, JSON.stringify(data))
  }
  
  static async del(key: string): Promise<void> {
    await redis.del(key)
  }
  
  static async exists(key: string): Promise<boolean> {
    const result = await redis.exists(key)
    return result === 1
  }
  
  // ==================== HASH OPERATIONS ====================
  
  static async hGet<T>(key: string, field: string): Promise<T | null> {
    const data = await redis.hget(key, field)
    return data ? JSON.parse(data) : null
  }
  
  static async hSet(key: string, field: string, value: any): Promise<void> {
    await redis.hset(key, field, JSON.stringify(value))
  }
  
  static async hDel(key: string, ...fields: string[]): Promise<void> {
    await redis.hdel(key, ...fields)
  }
  
  static async hGetAll<T>(key: string): Promise<Record<string, T>> {
    const data = await redis.hgetall(key)
    const result: Record<string, T> = {}
    
    for (const [k, v] of Object.entries(data)) {
      result[k] = JSON.parse(v)
    }
    
    return result
  }
  
  // ==================== LIST OPERATIONS ====================
  
  static async lPush<T>(key: string, ...values: T[]): Promise<number> {
    return redis.lpush(key, ...values.map(v => JSON.stringify(v)))
  }
  
  static async lRange<T>(key: string, start: number, stop: number): Promise<T[]> {
    const data = await redis.lrange(key, start, stop)
    return data.map(v => JSON.parse(v))
  }
  
  static async lTrim(key: string, start: number, stop: number): Promise<void> {
    await redis.ltrim(key, start, stop)
  }
  
  // ==================== SET OPERATIONS ====================
  
  static async sAdd<T>(key: string, ...values: T[]): Promise<number> {
    return redis.sadd(key, ...values.map(v => JSON.stringify(v)))
  }
  
  static async sMembers<T>(key: string): Promise<T[]> {
    const data = await redis.smembers(key)
    return data.map(v => JSON.parse(v))
  }
  
  static async sIsMember(key: string, value: any): Promise<boolean> {
    return (await redis.sismember(key, JSON.stringify(value))) === 1
  }
  
  // ==================== SORTED SET OPERATIONS ====================
  
  static async zAdd(key: string, score: number, value: any): Promise<void> {
    await redis.zadd(key, score, JSON.stringify(value))
  }
  
  static async zRangeByScore<T>(
    key: string, 
    min: number, 
    max: number,
    withScores?: boolean
  ): Promise<T[]> {
    const data = await redis.zrangebyscore(key, min, max, 'WITHSCORES' as any)
    // Handle withScores if needed
    return data.map(v => JSON.parse(v))
  }
  
  // ==================== INCREMENT OPERATIONS ====================
  
  static async incr(key: string): Promise<number> {
    return redis.incr(key)
  }
  
  static async incrBy(key: string, amount: number): Promise<number> {
    return redis.incrby(key, amount)
  }
  
  static async decr(key: string): Promise<number> {
    return redis.decr(key)
  }
  
  // ==================== EXPIRE OPERATIONS ====================
  
  static async expire(key: string, ttl: number): Promise<void> {
    await redis.expire(key, ttl)
  }
  
  static async ttl(key: string): Promise<number> {
    return redis.ttl(key)
  }
  
  // ==================== KEY PATTERN OPERATIONS ====================
  
  static async keys(pattern: string): Promise<string[]> {
    return redis.keys(pattern)
  }
  
  static async delByPattern(pattern: string): Promise<number> {
    const keys = await redis.keys(pattern)
    if (keys.length === 0) return 0
    return redis.del(...keys)
  }
  
  // ==================== TRANSACTION OPERATIONS ====================
  
  static async multi() {
    return redis.multi()
  }
  
  static async transaction<T>(fn: (multi: ReturnType<typeof redis.multi>) => void): Promise<T[]> {
    const multi = redis.multi()
    fn(multi)
    return multi.exec() as Promise<T[]>
  }
}
```

---

## 5. RATE LIMIT MIDDLEWARE EXAMPLE

### 5.1 Advanced Rate Limiter

```typescript
// middleware/rate-limit.middleware.ts
import { NextRequest, NextResponse } from 'next/server'
import { redis } from '@/lib/redis'

interface RateLimitRule {
  windowMs: number
  maxRequests: number
  blockDurationMs?: number
}

const RATE_LIMITS: Record<string, RateLimitRule> = {
  // Auth endpoints
  '/api/auth/login': { 
    windowMs: 15 * 60 * 1000, 
    maxRequests: 5,
    blockDurationMs: 15 * 60 * 1000,
  },
  '/api/auth/register': { 
    windowMs: 60 * 60 * 1000, 
    maxRequests: 3,
    blockDurationMs: 60 * 60 * 1000,
  },
  '/api/auth/forgot-password': { 
    windowMs: 60 * 60 * 1000, 
    maxRequests: 3,
    blockDurationMs: 60 * 60 * 1000,
  },
  '/api/auth/otp/verify': { 
    windowMs: 15 * 60 * 1000, 
    maxRequests: 10,
  },
  
  // API endpoints
  '/api/contact': { 
    windowMs: 60 * 1000, 
    maxRequests: 10,
  },
  '/api/comments': { 
    windowMs: 60 * 1000, 
    maxRequests: 20,
  },
  '/api/upload': { 
    windowMs: 60 * 60 * 1000, 
    maxRequests: 10,
  },
}

function getClientIdentifier(request: NextRequest): string {
  // Prefer user ID if authenticated
  const userId = request.headers.get('x-user-id')
  if (userId) return `user:${userId}`
  
  // Fall back to IP
  const forwarded = request.headers.get('x-forwarded-for')
  const ip = forwarded ? forwarded.split(',')[0].trim() : request.ip
  return `ip:${ip || 'unknown'}`
}

function matchRateLimitRule(pathname: string): RateLimitRule | null {
  // Exact match
  if (RATE_LIMITS[pathname]) {
    return RATE_LIMITS[pathname]
  }
  
  // Prefix match
  for (const pattern of Object.keys(RATE_LIMITS)) {
    if (pathname.startsWith(pattern)) {
      return RATE_LIMITS[pattern]
    }
  }
  
  return null
}

export async function rateLimitMiddleware(request: NextRequest) {
  const { nextUrl: url, method } = request
  
  // Skip rate limiting for GET requests (except sensitive ones)
  if (method === 'GET') {
    return NextResponse.next()
  }
  
  const rule = matchRateLimitRule(url.pathname)
  if (!rule) {
    return NextResponse.next()
  }
  
  const identifier = getClientIdentifier(request)
  const key = `ratelimit:${identifier}:${url.pathname}`
  
  // Check if blocked
  const blockedKey = `blocked:${identifier}`
  const isBlocked = await redis.get(blockedKey)
  
  if (isBlocked) {
    return NextResponse.json(
      { 
        error: 'Too many requests',
        message: 'You have been temporarily blocked. Please try again later.',
        retryAfter: await redis.ttl(blockedKey),
      },
      { 
        status: 429,
        headers: { 'Retry-After': String(await redis.ttl(blockedKey)) },
      }
    )
  }
  
  // Increment counter
  const currentCount = await redis.incr(key)
  
  // Set expiry on first request
  if (currentCount === 1) {
    await redis.expire(key, Math.ceil(rule.windowMs / 1000))
  }
  
  // Check if limit exceeded
  if (currentCount > rule.maxRequests) {
    // Block the client
    if (rule.blockDurationMs) {
      await redis.setex(blockedKey, Math.ceil(rule.blockDurationMs / 1000), '1')
    }
    
    return NextResponse.json(
      { 
        error: 'Rate limit exceeded',
        message: `Maximum ${rule.maxRequests} requests per ${rule.windowMs / 60000} minutes`,
      },
      { 
        status: 429,
        headers: { 
          'Retry-After': String(Math.ceil(rule.windowMs / 1000)),
          'X-RateLimit-Limit': String(rule.maxRequests),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(Date.now() + rule.windowMs),
        },
      }
    )
  }
  
  // Add rate limit headers to response
  const response = NextResponse.next()
  response.headers.set('X-RateLimit-Limit', String(rule.maxRequests))
  response.headers.set('X-RateLimit-Remaining', String(rule.maxRequests - currentCount))
  response.headers.set('X-RateLimit-Reset', String(Date.now() + rule.windowMs))
  
  return response
}
```

### 5.2 Rate Limiter Hook

```typescript
// hooks/use-rate-limit.ts
'use client'

import { useState, useCallback } from 'react'

interface RateLimitState {
  remaining: number
  reset: number
  limit: number
}

export function useRateLimit() {
  const [rateLimit, setRateLimit] = useState<RateLimitState | null>(null)
  
  const checkRateLimit = useCallback(async (endpoint: string) => {
    try {
      const response = await fetch(endpoint, { method: 'HEAD' })
      
      setRateLimit({
        remaining: parseInt(response.headers.get('X-RateLimit-Remaining') || '0'),
        reset: parseInt(response.headers.get('X-RateLimit-Reset') || '0'),
        limit: parseInt(response.headers.get('X-RateLimit-Limit') || '0'),
      })
      
      return response.ok
    } catch {
      return false
    }
  }, [])
  
  return { rateLimit, checkRateLimit }
}
```

---

## 6. CACHE IMPLEMENTATIONS

### 6.1 Product Caching

```typescript
// services/product-cache.service.ts
import { CacheService } from './cache.service'
import { TTL } from '@/lib/cache/ttl'
import { cacheKeys } from '@/lib/cache/keys'

export class ProductCacheService {
  // Get single product with caching
  static async getProduct(id: string) {
    return CacheService.get(`product:${id}`)
  }
  
  // Cache product
  static async cacheProduct(id: string, product: any) {
    await CacheService.set(`product:${id}`, product, TTL.PRODUCT)
  }
  
  // Invalidate product cache
  static async invalidateProduct(id: string) {
    await CacheService.del(`product:${id}`)
    // Also invalidate lists
    await CacheService.delByPattern('product:list:*')
  }
  
  // Get featured products
  static async getFeatured() {
    return CacheService.get('product:featured')
  }
  
  // Cache featured products
  static async cacheFeatured(products: any[]) {
    await CacheService.set('product:featured', products, TTL.PRODUCT_FEATURED)
  }
  
  // Get paginated products
  static async getProducts(page: number, limit: number, filters?: any) {
    const key = `product:list:${page}:${limit}:${JSON.stringify(filters || {})}`
    return CacheService.get(key)
  }
  
  // Cache paginated products
  static async cacheProducts(page: number, limit: number, filters: any, products: any[]) {
    const key = `product:list:${page}:${limit}:${JSON.stringify(filters)}`
    await CacheService.set(key, products, TTL.PRODUCT_LIST)
  }
}
```

### 6.2 Dashboard Caching

```typescript
// services/dashboard-cache.service.ts
import { CacheService } from './cache.service'
import { TTL } from '@/lib/cache/ttl'

export class DashboardCacheService {
  static async getSummary(role: string) {
    return CacheService.get(`dashboard:summary:${role}`)
  }
  
  static async cacheSummary(role: string, data: any) {
    await CacheService.set(`dashboard:summary:${role}`, data, TTL.DASHBOARD_SUMMARY)
  }
  
  static async invalidateSummary(role?: string) {
    if (role) {
      await CacheService.del(`dashboard:summary:${role}`)
    } else {
      await CacheService.delByPattern('dashboard:*')
    }
  }
  
  static async getSalesChart(type: 'daily' | 'monthly' | 'yearly', date: string) {
    return CacheService.get(`dashboard:sales:${type}:${date}`)
  }
  
  static async cacheSalesChart(type: 'daily' | 'monthly' | 'yearly', date: string, data: any) {
    await CacheService.set(`dashboard:sales:${type}:${date}`, data, TTL.DASHBOARD_STATS)
  }
}
```

---

## 7. SUMMARY

| Feature | Implementation |
|---------|----------------|
| Key Convention | `{prefix}:{entity}:{identifier}:{field}` |
| TTL Range | 60s (rate limit) to 24h (session) |
| Invalidation | On-write, pattern-based |
| Redis Client | ioredis with pipeline support |
| Rate Limiting | Per-IP + Per-User hybrid |

---

*Next Step: STEP 5 - Payment Integration (Midtrans)*
