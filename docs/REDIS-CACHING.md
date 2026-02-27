# STEP 4 — Redis Caching Strategy

## 1. Cache Architecture Overview

Redis is used for:
- Session storage
- API response caching
- Cart management
- OTP storage
- Rate limiting
- Real-time counters

---

## 2. Cache Key Structure Convention

```
Format: {prefix}:{resource}:{identifier}:{scope}

Examples:
- session:abc123...          → User session
- cart:user:user_123        → User cart
- product:catalog:page:1    → Product catalog page
- otp:user:user_123:login   → Login OTP
- rate:api:/api/products    → API rate limit
- dashboard:summary:admin    → Dashboard summary
```

### Key Prefixes
| Prefix | Purpose | TTL |
|--------|---------|-----|
| `session` | User sessions | 24h |
| `cart` | Shopping cart | 24h |
| `product` | Product data | 5min |
| `category` | Category data | 10min |
| `article` | Article cache | 5min |
| `dashboard` | Dashboard metrics | 1min |
| `otp` | OTP codes | 5min |
| `rate` | Rate limits | 1min |
| `search` | Search results | 10min |

---

## 3. TTL Strategy

| Data Type | TTL | Rationale |
|-----------|-----|-----------|
| Sessions | 24h (sliding) | User activity |
| Cart | 24h | Abandoned carts |
| Product Catalog | 5min | Balance freshness/performance |
| Dashboard | 1min | Real-time metrics |
| OTP | 5min (absolute) | Security |
| Rate Limit | 1min | Short-lived |
| Search | 10min | Expensive queries |
| User Profile | 15min | Infrequently updated |

---

## 4. Invalidation Strategy

### 4.1 Write-Through
```
User updates product → Update DB → Invalidate product cache → Write new cache
```

### 4.2 Cache-Aside
```
1. Check cache → hit → return
2. Cache miss → Fetch DB → Store cache → Return
```

### 4.3 Event-Based Invalidation
```
Product Updated → Publish event → All instances invalidate cache
```

### 4.4 Invalidation Patterns

| Action | Invalidate |
|--------|------------|
| Product created | `product:catalog:*`, `product:{id}` |
| Product updated | `product:{id}`, `product:catalog:*` |
| Product deleted | `product:{id}`, `product:catalog:*` |
| Order created | `dashboard:*`, `user:{id}:orders` |
| Payment completed | `dashboard:*`, `order:{id}` |

---

## 5. Redis Utility Configuration

### 5.1 Redis Client (`src/lib/redis.ts`)

```typescript
// src/lib/redis.ts
import { createClient, RedisClientType } from 'redis';

let redisClient: RedisClientType | null = null;

export async function getRedisClient(): Promise<RedisClientType> {
  if (redisClient && redisClient.isOpen) {
    return redisClient;
  }

  redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) {
          return new Error('Redis reconnection failed');
        }
        return Math.min(retries * 100, 3000);
      },
    },
  });

  redisClient.on('error', (err) => {
    console.error('Redis Client Error:', err);
  });

  await redisClient.connect();
  return redisClient;
}

// Singleton accessor
export const redis = {
  async get(key: string): Promise<string | null> {
    const client = await getRedisClient();
    return client.get(key);
  },

  async set(key: string, value: string, ttl?: number): Promise<void> {
    const client = await getRedisClient();
    if (ttl) {
      await client.setEx(key, ttl, value);
    } else {
      await client.set(key, value);
    }
  },

  async del(...keys: string[]): Promise<void> {
    const client = await getRedisClient();
    await client.del(...keys);
  },

  async incr(key: string): Promise<number> {
    const client = await getRedisClient();
    return client.incr(key);
  },

  async expire(key: string, ttl: number): Promise<void> {
    const client = await getRedisClient();
    await client.expire(key, ttl);
  },

  async keys(pattern: string): Promise<string[]> {
    const client = await getRedisClient();
    return client.keys(pattern);
  },

  async hGetAll(key: string): Promise<Record<string, string>> {
    const client = await getRedisClient();
    return client.hGetAll(key);
  },

  async hSet(key: string, field: string, value: string): Promise<void> {
    const client = await getRedisClient();
    await client.hSet(key, field, value);
  },

  async publish(channel: string, message: string): Promise<number> {
    const client = await getRedisClient();
    return client.publish(channel, message);
  },
};
```

### 5.2 Cache Service (`src/services/CacheService.ts`)

```typescript
// src/services/CacheService.ts
import { redis } from '@/lib/redis';

export interface CacheOptions {
  ttl?: number; // seconds
  prefix?: string;
}

export class CacheService {
  private defaultTTL = 300; // 5 minutes

  // Generate cache key
  key(resource: string, ...parts: string[]): string {
    return [resource, ...parts].join(':');
  }

  // Get cached data
  async get<T>(key: string): Promise<T | null> {
    try {
      const data = await redis.get(key);
      if (!data) return null;
      return JSON.parse(data) as T;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  // Set cached data
  async set<T>(key: string, data: T, options?: CacheOptions): Promise<void> {
    try {
      const ttl = options?.ttl || this.defaultTTL;
      await redis.set(key, JSON.stringify(data), ttl);
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  // Delete cached data
  async invalidate(key: string): Promise<void> {
    try {
      await redis.del(key);
    } catch (error) {
      console.error('Cache invalidate error:', error);
    }
  }

  // Delete by pattern
  async invalidatePattern(pattern: string): Promise<void> {
    try {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } catch (error) {
      console.error('Cache invalidate pattern error:', error);
    }
  }

  // Cache function result
  async remember<T>(
    key: string,
    fn: () => Promise<T>,
    options?: CacheOptions
  ): Promise<T> {
    const cached = await this.get<T>(key);
    if (cached) return cached;

    const data = await fn();
    await this.set(key, data, options);
    return data;
  }

  // Product catalog cache
  async getProductCatalog(
    page: number,
    limit: number,
    category?: string
  ): Promise<any[] | null> {
    const key = this.key('product', 'catalog', `page:${page}`, `limit:${limit}`, category || 'all');
    return this.get(key);
  }

  async setProductCatalog(
    page: number,
    limit: number,
    category: string | undefined,
    data: any[]
  ): Promise<void> {
    const key = this.key('product', 'catalog', `page:${page}`, `limit:${limit}`, category || 'all');
    await this.set(key, data, { ttl: 300 });
  }

  async invalidateProductCache(productId?: string): Promise<void> {
    if (productId) {
      await this.invalidate(this.key('product', productId));
    }
    await this.invalidatePattern('product:catalog:*');
    await this.invalidatePattern('product:featured:*');
  }

  // Dashboard cache
  async getDashboardSummary(role: string): Promise<any | null> {
    return this.get(this.key('dashboard', 'summary', role));
  }

  async setDashboardSummary(role: string, data: any): Promise<void> {
    await this.set(this.key('dashboard', 'summary', role), data, { ttl: 60 });
  }

  async invalidateDashboardCache(): Promise<void> {
    await this.invalidatePattern('dashboard:*');
  }
}

export const cacheService = new CacheService();
```

---

## 6. Rate Limiting Implementation

### 6.1 Rate Limit Service (`src/services/RateLimitService.ts`)

```typescript
// src/services/RateLimitService.ts
import { redis } from '@/lib/redis';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export class RateLimitService {
  private defaultWindowMs = 60000; // 1 minute
  private defaultMaxRequests = 100;

  async check(
    identifier: string,
    endpoint: string,
    maxRequests: number = this.defaultMaxRequests,
    windowMs: number = this.defaultWindowMs
  ): Promise<RateLimitResult> {
    const key = `rate:${endpoint}:${identifier}`;
    const windowSeconds = Math.ceil(windowMs / 1000);

    const current = await redis.get(key);
    const count = current ? parseInt(current) : 0;

    const remaining = Math.max(0, maxRequests - count - 1);
    const resetAt = Date.now() + windowMs;

    if (count >= maxRequests) {
      return { allowed: false, remaining: 0, resetAt };
    }

    // Increment counter
    const pipeline = redis as any;
    await pipeline.incr(key);
    if (count === 0) {
      await pipeline.expire(key, windowSeconds);
    }

    return { allowed: true, remaining, resetAt };
  }

  // Sliding window rate limiter (more accurate)
  async slidingCheck(
    identifier: string,
    endpoint: string,
    maxRequests: number = this.defaultMaxRequests,
    windowMs: number = this.defaultWindowMs
  ): Promise<RateLimitResult> {
    const key = `rate:sliding:${endpoint}:${identifier}`;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Remove old entries
    const current = await redis.zrangebyscore(key, windowStart, now);
    
    if (current.length >= maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: now + windowMs,
      };
    }

    // Add new entry
    await redis.zadd(key, now, `${now}:${Math.random()}`);
    await redis.expire(key, Math.ceil(windowMs / 1000));

    return {
      allowed: true,
      remaining: maxRequests - current.length - 1,
      resetAt: now + windowMs,
    };
  }
}

export const rateLimitService = new RateLimitService();
```

### 6.2 Rate Limit Middleware (`src/middleware/rateLimit.ts`)

```typescript
// src/middleware/rateLimit.ts
import { NextRequest, NextResponse } from 'next/server';
import { rateLimitService } from '@/services/RateLimitService';

const RATE_LIMITS = {
  default: { max: 100, windowMs: 60000 },
  auth: { max: 5, windowMs: 900000 }, // 5 attempts per 15 min
  login: { max: 3, windowMs: 900000 },
  api: { max: 200, windowMs: 60000 },
  upload: { max: 10, windowMs: 60000 },
};

export async function rateLimitMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname, ip } = request.nextUrl;

  // Determine rate limit config
  let config = RATE_LIMITS.default;
  
  if (pathname.includes('/auth/login')) {
    config = RATE_LIMITS.login;
  } else if (pathname.includes('/auth')) {
    config = RATE_LIMITS.auth;
  } else if (pathname.startsWith('/api/upload')) {
    config = RATE_LIMITS.upload;
  } else if (pathname.startsWith('/api')) {
    config = RATE_LIMITS.api;
  }

  // Get identifier
  const userId = request.headers.get('x-user-id');
  const identifier = userId || ip || 'anonymous';

  // Check rate limit
  const result = await rateLimitService.check(
    identifier,
    pathname,
    config.max,
    config.windowMs
  );

  if (!result.allowed) {
    const response = NextResponse.json(
      { error: 'Too many requests', retryAfter: Math.ceil((result.resetAt - Date.now()) / 1000) },
      { status: 429 }
    );
    response.headers.set('X-RateLimit-Remaining', '0');
    response.headers.set('X-RateLimit-Reset', result.resetAt.toString());
    return response;
  }

  // Add rate limit headers
  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Remaining', result.remaining.toString());
  response.headers.set('X-RateLimit-Reset', result.resetAt.toString());

  return response;
}
```

---

## 7. Session Storage

### 7.1 Session Repository (`src/repositories/SessionRepository.ts`)

```typescript
// src/repositories/SessionRepository.ts
import { redis } from '@/lib/redis';
import crypto from 'crypto';

const SESSION_PREFIX = 'session:';
const SESSION_TTL = 24 * 60 * 60; // 24 hours

export interface Session {
  userId: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  createdAt: number;
  ipAddress?: string;
  userAgent?: string;
}

export class SessionRepository {
  private hashToken(token: string): string {
    const salt = process.env.SESSION_SECRET || 'default-salt';
    return crypto.createHmac('sha256', salt).update(token).digest('hex');
  }

  async create(session: Omit<Session, 'createdAt'>): Promise<string> {
    const token = crypto.randomUUID() + ':' + Date.now();
    const key = SESSION_PREFIX + this.hashToken(token);
    
    await redis.set(key, JSON.stringify({ ...session, createdAt: Date.now() }), SESSION_TTL);
    
    return token;
  }

  async get(token: string): Promise<Session | null> {
    const key = SESSION_PREFIX + this.hashToken(token);
    const data = await redis.get(key);
    
    if (!data) return null;
    
    // Sliding expiration
    await redis.expire(key, SESSION_TTL);
    
    return JSON.parse(data);
  }

  async invalidate(token: string): Promise<void> {
    const key = SESSION_PREFIX + this.hashToken(token);
    await redis.del(key);
  }

  async invalidateUserSessions(userId: string): Promise<void> {
    // Note: In production, maintain a user->sessions index
    const keys = await redis.keys(SESSION_PREFIX + '*');
    
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const session: Session = JSON.parse(data);
        if (session.userId === userId) {
          await redis.del(key);
        }
      }
    }
  }
}

export const sessionRepository = new SessionRepository();
```

---

## 8. Cart Caching

### 8.1 Cart Service with Redis (`src/services/CartService.ts`)

```typescript
// src/services/CartService.ts
import { db } from '@/lib/db';
import { redis } from '@/lib/redis';

const CART_PREFIX = 'cart:user:';
const CART_TTL = 24 * 60 * 60; // 24 hours

export interface CartItem {
  productId: string;
  productName: string;
  productImage?: string;
  price: number;
  quantity: number;
}

export interface Cart {
  userId: string;
  items: CartItem[];
  totalItems: number;
  totalPrice: number;
  updatedAt: number;
}

export class CartService {
  private getKey(userId: string): string {
    return CART_PREFIX + userId;
  }

  async getCart(userId: string): Promise<Cart | null> {
    // Try Redis first
    const cached = await redis.get(this.getKey(userId));
    if (cached) {
      return JSON.parse(cached);
    }

    // Fallback to DB
    const cart = await db.cart.findUnique({
      where: { userId },
      include: {
        items: {
          include: {
            product: {
              select: {
                id: true,
                name: true,
                price: true,
                images: { where: { isPrimary: true }, take: 1 },
              },
            },
          },
        },
      },
    });

    if (!cart) return null;

    const cartData: Cart = {
      userId: cart.userId,
      items: cart.items.map((item) => ({
        productId: item.productId,
        productName: item.product.name,
        productImage: item.product.images[0]?.url,
        price: Number(item.product.price),
        quantity: item.quantity,
      })),
      totalItems: cart.items.reduce((sum, item) => sum + item.quantity, 0),
      totalPrice: cart.items.reduce((sum, item) => sum + Number(item.product.price) * item.quantity, 0),
      updatedAt: Date.now(),
    };

    // Cache for next request
    await redis.set(this.getKey(userId), JSON.stringify(cartData), CART_TTL);

    return cartData;
  }

  async addItem(userId: string, productId: string, quantity: number = 1): Promise<Cart> {
    // Get product
    const product = await db.product.findUnique({
      where: { id: productId },
    });

    if (!product) {
      throw new Error('Product not found');
    }

    // Check stock
    if (product.stock < quantity) {
      throw new Error('Insufficient stock');
    }

    // Update DB
    const cart = await db.cart.upsert({
      where: { userId },
      create: { userId },
      include: { items: true },
    });

    const existingItem = cart.items.find((item) => item.productId === productId);

    if (existingItem) {
      await db.cartItem.update({
        where: { id: existingItem.id },
        data: { quantity: { increment: quantity } },
      });
    } else {
      await db.cartItem.create({
        data: {
          cartId: cart.id,
          productId,
          quantity,
        },
      });
    }

    // Invalidate cache
    await redis.del(this.getKey(userId));

    // Return updated cart
    return this.getCart(userId) as Promise<Cart>;
  }

  async removeItem(userId: string, productId: string): Promise<Cart> {
    const cart = await db.cart.findUnique({
      where: { userId },
      include: { items: true },
    });

    if (!cart) {
      throw new Error('Cart not found');
    }

    const item = cart.items.find((i) => i.productId === productId);
    if (item) {
      await db.cartItem.delete({ where: { id: item.id } });
    }

    // Invalidate cache
    await redis.del(this.getKey(userId));

    return this.getCart(userId) as Promise<Cart>;
  }

  async clearCart(userId: string): Promise<void> {
    await db.cartItem.deleteMany({
      where: { cart: { userId } },
    });

    await redis.del(this.getKey(userId));
  }
}

export const cartService = new CartService();
```

---

## 9. Search Caching

### 9.1 Search Service (`src/services/SearchService.ts`)

```typescript
// src/services/SearchService.ts
import { db } from '@/lib/db';
import { redis } from '@/lib/redis';

const SEARCH_PREFIX = 'search:';
const SEARCH_TTL = 10 * 60; // 10 minutes

export class SearchService {
  async searchProducts(
    query: string,
    options: {
      category?: string;
      minPrice?: number;
      maxPrice?: number;
      sort?: 'price_asc' | 'price_desc' | 'name' | 'newest';
      page?: number;
      limit?: number;
    } = {}
  ): Promise<{ products: any[]; total: number }> {
    const { category, minPrice, maxPrice, sort = 'newest', page = 1, limit = 20 } = options;
    
    // Generate cache key
    const cacheKey = SEARCH_PREFIX + `products:${query}:${JSON.stringify(options)}`;

    // Try cache
    const cached = await redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Build query
    const where: any = {
      status: 'PUBLISHED',
      deletedAt: null,
      OR: [
        { name: { contains: query, mode: 'insensitive' } },
        { description: { contains: query, mode: 'insensitive' } },
      ],
    };

    if (category) {
      where.category = { slug: category };
    }

    if (minPrice !== undefined || maxPrice !== undefined) {
      where.price = {};
      if (minPrice !== undefined) where.price.gte = minPrice;
      if (maxPrice !== undefined) where.price.lte = maxPrice;
    }

    // Sort mapping
    const orderBy: any = {};
    switch (sort) {
      case 'price_asc':
        orderBy.price = 'asc';
        break;
      case 'price_desc':
        orderBy.price = 'desc';
        break;
      case 'name':
        orderBy.name = 'asc';
        break;
      default:
        orderBy.createdAt = 'desc';
    }

    const [products, total] = await Promise.all([
      db.product.findMany({
        where,
        orderBy,
        skip: (page - 1) * limit,
        take: limit,
        include: {
          category: true,
          images: { where: { isPrimary: true }, take: 1 },
        },
      }),
      db.product.count({ where }),
    ]);

    const result = { products, total };

    // Cache result
    await redis.set(cacheKey, JSON.stringify(result), SEARCH_TTL);

    return result;
  }

  async invalidateSearchCache(): Promise<void> {
    const keys = await redis.keys(SEARCH_PREFIX + '*');
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  }
}

export const searchService = new SearchService();
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
