# STEP 10 — Security Hardening

## 1. Security Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      REQUEST LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────┤
│  Request → Rate Limit → CSRF → Auth → RBAC → Validation → DB  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. CSRF Middleware (`src/middleware/csrf.ts`)

```typescript
// src/middleware/csrf.ts
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';

export function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export async function csrfMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const method = request.method;
  
  // Only protect state-changing methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return null;
  }

  // Skip for webhooks (they have their own signature verification)
  if (request.nextUrl.pathname.startsWith('/api/webhooks')) {
    return null;
  }

  // Skip for auth endpoints that handle their own CSRF
  const skipPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/forgot-password',
  ];
  
  if (skipPaths.some(path => request.nextUrl.pathname.startsWith(path))) {
    return null;
  }

  const csrfCookie = request.cookies.get(CSRF_COOKIE)?.value;
  const csrfHeader = request.headers.get(CSRF_HEADER);

  // For GET requests, just generate/set token
  if (method === 'GET') {
    return null;
  }

  // Validate CSRF token
  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return NextResponse.json(
      { error: 'CSRF validation failed' },
      { status: 403 }
    );
  }

  return null;
}
```

---

## 3. Rate Limiting Middleware (`src/middleware/rateLimit.ts`)

```typescript
// src/middleware/rateLimit.ts
import { NextRequest, NextResponse } from 'next/server';
import { redis } from '@/lib/redis';

const RATE_LIMIT_PREFIX = 'ratelimit:';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  // General API: 100 requests per minute
  default: { windowMs: 60000, maxRequests: 100 },
  
  // Auth endpoints: Stricter limits
  auth: { windowMs: 900000, maxRequests: 5 }, // 5 per 15 minutes
  login: { windowMs: 900000, maxRequests: 3 }, // 3 per 15 minutes
  
  // API endpoints: 200 per minute
  api: { windowMs: 60000, maxRequests: 200 },
  
  // File uploads: 10 per minute
  upload: { windowMs: 60000, maxRequests: 10 },
};

export async function rateLimitMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname, ip } = request.nextUrl;

  // Determine rate limit tier
  let tier = 'default';
  if (pathname.includes('/auth/login')) tier = 'login';
  else if (pathname.startsWith('/api/auth')) tier = 'auth';
  else if (pathname.startsWith('/api/upload')) tier = 'upload';
  else if (pathname.startsWith('/api')) tier = 'api';

  const config = RATE_LIMITS[tier];

  // Get identifier (user ID or IP)
  const userId = request.headers.get('x-user-id');
  const identifier = userId || ip || 'anonymous';
  const key = `${RATE_LIMIT_PREFIX}${tier}:${identifier}`;

  try {
    // Get current count
    const current = await redis.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= config.maxRequests) {
      const response = NextResponse.json(
        { 
          error: 'Too many requests',
          retryAfter: Math.ceil(config.windowMs / 1000)
        },
        { status: 429 }
      );
      response.headers.set('Retry-After', String(Math.ceil(config.windowMs / 1000)));
      response.headers.set('X-RateLimit-Limit', String(config.maxRequests));
      response.headers.set('X-RateLimit-Remaining', '0');
      return response;
    }

    // Increment counter
    const ttl = Math.ceil(config.windowMs / 1000);
    if (count === 0) {
      await redis.setex(key, ttl, '1');
    } else {
      await redis.incr(key);
    }

    // Add rate limit headers to response
    return NextResponse.next();
  } catch (error) {
    // If Redis fails, allow request but log error
    console.error('Rate limit error:', error);
    return null;
  }
}
```

---

## 4. Image Validation Middleware (`src/middleware/validateImage.ts`)

```typescript
// src/middleware/validateImage.ts
import { NextRequest, NextResponse } from 'next/server';

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
];

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Magic bytes for image validation
const MAGIC_BYTES: Record<string, number[]> = {
  'jpeg': [0xFF, 0xD8, 0xFF],
  'png': [0x89, 0x50, 0x4E, 0x47],
  'gif': [0x47, 0x49, 0x46],
  'webp': [0x52, 0x49, 0x46, 0x46], // RIFF....WEBP
};

export async function validateImageMiddleware(request: NextRequest): Promise<NextResponse | null> {
  // Only apply to upload endpoints
  if (!request.nextUrl.pathname.startsWith('/api/upload')) {
    return null;
  }

  // For FormData (file uploads)
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('multipart/form-data')) {
    // Let the API handler validate the actual file
    // This middleware just checks the content-type header
    return null;
  }

  // Validate content-type for JSON API
  if (contentType.includes('application/json')) {
    try {
      const body = await request.json();
      
      // Validate file data if provided as base64
      if (body.imageData) {
        const matches = body.imageData.match(/^data:([^;]+);base64,(.+)$/);
        if (matches) {
          const mimeType = matches[1];
          if (!ALLOWED_MIME_TYPES.includes(mimeType)) {
            return NextResponse.json(
              { error: 'Invalid image type. Allowed: JPEG, PNG, GIF, WebP' },
              { status: 400 }
            );
          }
        }
      }
    } catch {
      // Invalid JSON, let JSON parser handle error
    }
  }

  return null;
}

// Helper function to validate actual file buffer
export function validateImageBuffer(buffer: Buffer): { valid: boolean; error?: string } {
  if (buffer.length < 4) {
    return { valid: false, error: 'File too small' };
  }

  if (buffer.length > MAX_FILE_SIZE) {
    return { valid: false, error: 'File too large (max 10MB)' };
  }

  // Check magic bytes
  const isJpeg = MAGIC_BYTES.jpeg.every((byte, i) => buffer[i] === byte);
  const isPng = MAGIC_BYTES.png.every((byte, i) => buffer[i] === byte);
  const isGif = MAGIC_BYTES.gif.every((byte, i) => buffer[i] === byte);
  const isWebp = buffer.slice(0, 4).toString() === 'RIFF' && buffer.slice(8, 12).toString() === 'WEBP';

  if (!isJpeg && !isPng && !isGif && !isWebp) {
    return { valid: false, error: 'Invalid image format' };
  }

  return { valid: true };
}
```

---

## 5. API Validation using Zod

### 5.1 Validation Middleware (`src/middleware/validate.ts`)

```typescript
// src/middleware/validate.ts
import { NextRequest, NextResponse } from 'next/server';
import { ZodSchema, ZodError } from 'zod';

export function validateRequest(schema: ZodSchema) {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    try {
      let body: any;

      const contentType = request.headers.get('content-type') || '';

      if (contentType.includes('application/json')) {
        body = await request.json();
      } else if (contentType.includes('multipart/form-data')) {
        // For FormData, let the API handler validate
        return null;
      }

      // Validate against schema
      const validated = schema.parse(body);

      // Create a new request with validated body
      const { clone } = request;
      return NextResponse.next();
    } catch (error) {
      if (error instanceof ZodError) {
        return NextResponse.json(
          {
            error: 'Validation failed',
            details: error.errors.map((e) => ({
              path: e.path.join('.'),
              message: e.message,
            })),
          },
          { status: 400 }
        );
      }

      return NextResponse.json(
        { error: 'Invalid request' },
        { status: 400 }
      );
    }
  };
}
```

### 5.2 Validation Examples (`src/validations/index.ts`)

```typescript
// src/validations/index.ts
import { z } from 'zod';

// Common validation rules
export const emailSchema = z.string().email('Invalid email address');
export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number');

export const uuidSchema = z.string().uuid('Invalid UUID');

export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(10),
});

// Product validations
export const productSchema = z.object({
  name: z.string().min(1, 'Name is required').max(200),
  slug: z.string().max(200).optional(),
  description: z.string().optional(),
  price: z.number().positive('Price must be positive'),
  costPrice: z.number().positive().optional(),
  stock: z.number().int().min(0).default(0),
  sku: z.string().max(100).optional(),
  categoryId: uuidSchema.optional(),
  status: z.enum(['DRAFT', 'PUBLISHED', 'ARCHIVED']).default('DRAFT'),
  featured: z.boolean().default(false),
});

// Order validations
export const orderSchema = z.object({
  customerName: z.string().min(1, 'Customer name is required'),
  customerEmail: emailSchema,
  customerPhone: z.string().optional(),
  shippingAddress: z.string().optional(),
  shippingCity: z.string().optional(),
  shippingProvince: z.string().optional(),
  shippingPostalCode: z.string().optional(),
  notes: z.string().optional(),
  items: z.array(z.object({
    productId: uuidSchema,
    quantity: z.number().int().positive(),
  })).min(1, 'At least one item is required'),
});
```

---

## 6. Environment Validation (`src/lib/env.ts`)

```typescript
// src/lib/env.ts
import { z } from 'zod';

const envSchema = z.object({
  // Database
  DATABASE_URL: z.string().url(),
  
  // Redis
  REDIS_URL: z.string().url().optional(),
  
  // Auth
  SESSION_SECRET: z.string().min(32, 'Session secret must be at least 32 characters'),
  OTP_SECRET: z.string().min(16),
  
  // Email
  SMTP_HOST: z.string(),
  SMTP_PORT: z.coerce.number(),
  SMTP_USER: z.string(),
  SMTP_PASS: z.string(),
  SMTP_FROM_EMAIL: z.string().email(),
  SMTP_FROM_NAME: z.string(),
  
  // Midtrans
  MIDTRANS_SERVER_KEY: z.string(),
  MIDTRANS_CLIENT_KEY: z.string(),
  MIDTRANS_ENV: z.enum(['sandbox', 'production']).default('sandbox'),
  
  // App
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  APP_URL: z.string().url(),
  
  // Security
  CSRF_SECRET: z.string().min(32),
});

export function validateEnv() {
  try {
    envSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('Environment validation failed:');
      error.errors.forEach((e) => {
        console.error(`  - ${e.path.join('.')}: ${e.message}`);
      });
    }
    process.exit(1);
  }
}

// Run validation on startup
validateEnv();

export const env = envSchema.parse(process.env);
```

---

## 7. Error Boundary (`src/app/error.tsx`)

```typescript
// src/app/error.tsx
'use client';

import { useEffect } from 'react';
import { Button } from '@/components/ui/button';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log error to error reporting service
    console.error('Application error:', error);
  }, [error]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <h2 className="text-2xl font-bold mb-4">Something went wrong!</h2>
        <p className="text-muted-foreground mb-4">
          {error.message || 'An unexpected error occurred'}
        </p>
        {error.digest && (
          <p className="text-xs text-muted-foreground mb-4">
            Error ID: {error.digest}
          </p>
        )}
        <Button onClick={reset}>Try again</Button>
      </div>
    </div>
  );
}
```

---

## 8. Logging Strategy (`src/lib/logger.ts`)

```typescript
// src/lib/logger.ts
type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  [key: string]: any;
}

class Logger {
  private isProduction = process.env.NODE_ENV === 'production';

  private formatMessage(level: LogLevel, message: string, context?: LogContext): string {
    const timestamp = new Date().toISOString();
    const contextStr = context ? ` ${JSON.stringify(context)}` : '';
    return `[${timestamp}] ${level.toUpperCase()}: ${message}${contextStr}`;
  }

  debug(message: string, context?: LogContext) {
    if (!this.isProduction) {
      console.debug(this.formatMessage('debug', message, context));
    }
  }

  info(message: string, context?: LogContext) {
    console.info(this.formatMessage('info', message, context));
  }

  warn(message: string, context?: LogContext) {
    console.warn(this.formatMessage('warn', message, context));
  }

  error(message: string, error?: Error, context?: LogContext) {
    const errorContext = error
      ? {
          ...context,
          error: {
            message: error.message,
            stack: this.isProduction ? undefined : error.stack,
          },
        }
      : context;

    console.error(this.formatMessage('error', message, errorContext));

    // In production, send to error tracking service
    // await sendToErrorTracker(error, context);
  }
}

export const logger = new Logger();

// API route wrapper with logging
export function withLogging<T extends (...args: any[]) => any>(fn: T): T {
  return (async (req: Request, ...args: any[]) => {
    const start = Date.now();
    const { pathname } = new URL(req.url);

    logger.info('API Request', { method: req.method, path: pathname });

    try {
      const response = await fn(req, ...args);
      const duration = Date.now() - start;

      logger.info('API Response', {
        method: req.method,
        path: pathname,
        status: response.status,
        duration: `${duration}ms`,
      });

      return response;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('API Error', error as Error, {
        method: req.method,
        path: pathname,
        duration: `${duration}ms`,
      });
      throw error;
    }
  }) as T;
}
```

---

## 9. Backup Strategy Recommendation

### 9.1 Database Backups
```yaml
# docker-compose.backup.yml
services:
  db-backup:
    image: postgres-backup:latest
    environment:
      POSTGRES_HOST: ${POSTGRES_HOST}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      BACKUP_SCHEDULE: "0 2 * * *"  # Daily at 2 AM
      BACKUP_RETENTION: 30  # Keep 30 days
    volumes:
      - ./backups:/backups
```

### 9.2 Backup Script
```bash
#!/bin/bash
# scripts/backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="./backups"

# Database backup
pg_dump "$DATABASE_URL" > "$BACKUP_DIR/db_$DATE.sql"

# Upload to cloud storage (AWS S3, GCS, etc.)
aws s3 cp "$BACKUP_DIR/db_$DATE.sql" "s3://your-bucket/backups/"

# Clean old local backups (keep 7 days)
find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
```

---

## 10. Data Retention Policy

| Data Type | Retention | Action |
|-----------|-----------|--------|
| Transaction logs | 7 years | Archive → Delete |
| Activity logs | 1 year | Delete |
| Session data | 24 hours | Auto-delete |
| OTP codes | 15 minutes | Auto-delete |
| Payment records | 7 years | Archive → Delete |
| User data | Account lifetime | Soft delete on account deletion |
| Order data | 7 years | Archive → Delete |
| Visitor analytics | 90 days | Aggregate → Delete raw |

---

## 11. API Versioning Preparation

```typescript
// src/middleware/apiVersion.ts
import { NextRequest, NextResponse } from 'next/server';

const API_VERSIONS = ['v1'];

export async function apiVersionMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname } = request.nextUrl;

  // Only apply to /api routes
  if (!pathname.startsWith('/api/')) {
    return null;
  }

  // Check for version in header or URL
  const versionHeader = request.headers.get('x-api-version');
  const versionMatch = pathname.match(/^\/api\/(v\d+)\//);
  const urlVersion = versionMatch ? versionMatch[1] : null;

  const version = versionHeader || urlVersion || 'v1';

  if (!API_VERSIONS.includes(version)) {
    return NextResponse.json(
      { error: `API version not supported. Supported: ${API_VERSIONS.join(', ')}` },
      { status: 400 }
    );
  }

  // Add version to request headers for handlers
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-api-version', version);

  return NextResponse.next({
    request: { headers: requestHeaders },
  });
}
```

---

## 12. Multi-Tenant Preparation Design

```typescript
// Multi-tenant middleware concept
export async function tenantMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname, hostname } = request.nextUrl;

  // Extract tenant from subdomain or path
  const subdomain = hostname.split('.')[0];
  
  // Skip for API paths with explicit tenant
  if (pathname.startsWith('/api/tenants')) {
    return null;
  }

  // For API routes, extract tenant from header
  const tenantId = request.headers.get('x-tenant-id');
  
  if (tenantId) {
    // Validate tenant exists
    const tenant = await prisma.tenant.findUnique({ where: { id: tenantId } });
    if (!tenant) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 403 });
    }

    // Add tenant context
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-tenant-id', tenantId);

    return NextResponse.next({ request: { headers: requestHeaders } });
  }

  return null;
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
