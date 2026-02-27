# STEP 3: Authentication & RBAC Implementation

## Enterprise CMS Company Profile - Auth Architecture

---

## 1. AUTHENTICATION FLOW EXPLANATION

### 1.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AUTHENTICATION FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────┐                                                               │
│  │  Client  │                                                               │
│  └────┬─────┘                                                               │
│       │                                                                     │
│       │ POST /api/auth/register                                             │
│       │─────────────────────────────────────────────────────────────────►  │
│       │                                                                     │
│       │                     ┌──────────────────────┐                        │
│       │                     │    Server Actions    │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Validate Input │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     │          │           │                        │
│       │                     │          ▼           │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Hash Password  │  │                        │
│       │                     │  │ (bcrypt)       │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     │          │           │                        │
│       │                     │          ▼           │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Create User    │  │                        │
│       │                     │  │ + OTP Record   │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     │          │           │                        │
│       │                     │          ▼           │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Send OTP Email │  │                        │
│       │                     │  │ (Nodemailer)   │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     └──────────┼───────────┘                        │
│       │                                │                                     │
│       │◄────────────────────────────────────────────────────────────────   │
│       │         { success: true, message: "Verify email" }                 │
│       │                                                                     │
│       │ POST /api/auth/verify-email                                        │
│       │─────────────────────────────────────────────────────────────────►  │
│       │                                                                     │
│       │                     ┌──────────────────────┐                        │
│       │                     │    Server Actions    │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Validate OTP   │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     │          │           │                        │
│       │                     │          ▼           │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Update User    │  │                        │
│       │                     │  │ emailVerified  │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     │          │           │                        │
│       │                     │          ▼           │                        │
│       │                     │  ┌────────────────┐  │                        │
│       │                     │  │ Create Session │  │                        │
│       │                     │  │ (Redis)        │  │                        │
│       │                     │  └───────┬────────┘  │                        │
│       │                     └──────────┼───────────┘                        │
│       │                                │                                     │
│       │◄────────────────────────────────────────────────────────────────   │
│       │         { success: true, sessionToken }                            │
│       │                                                                     │
│       │                          ▼                                          │
│       │              Set HTTP-Only Cookie                                  │
│       │                                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Register Flow

```typescript
// app/api/auth/register/action.ts
'use server'

import { registerSchema } from '@/lib/validators/auth.validator'
import { db } from '@/lib/db'
import { redis } from '@/lib/redis'
import { emailService } from '@/services/email.service'
import bcrypt from 'bcryptjs'

export async function register(formData: FormData) {
  // 1. Validate input
  const data = registerSchema.parse(Object.fromEntries(formData))
  
  // 2. Check existing user
  const existing = await db.user.findUnique({
    where: { email: data.email }
  })
  
  if (existing) {
    throw new Error('Email already registered')
  }
  
  // 3. Hash password
  const hashedPassword = await bcrypt.hash(data.password, 12)
  
  // 4. Get default customer role
  const defaultRole = await db.role.findFirst({
    where: { type: 'CUSTOMER', isDefault: true }
  })
  
  // 5. Create user
  const user = await db.user.create({
    data: {
      email: data.email,
      password: hashedPassword,
      name: data.name,
      roleId: defaultRole?.id,
      status: 'PENDING', // Needs email verification
    }
  })
  
  // 6. Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString()
  
  await db.oTPVerification.create({
    data: {
      userId: user.id,
      email: user.email,
      otp,
      type: 'VERIFY_EMAIL',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    }
  })
  
  // 7. Store OTP in Redis for quick validation
  await redis.setex(
    `otp:${user.email}`,
    300, // 5 minutes
    otp
  )
  
  // 8. Send email
  await emailService.sendOTP(user.email, otp, 'Verify Your Email')
  
  return { success: true, message: 'Verification email sent' }
}
```

### 1.3 Email Verification Flow

```typescript
// app/api/auth/verify-email/action.ts
'use server'

import { verifyOtpSchema } from '@/lib/validators/auth.validator'
import { db } from '@/lib/db'
import { redis } from '@/lib/redis'
import { authService } from '@/services/auth.service'

export async function verifyEmail(formData: FormData) {
  const { email, otp } = verifyOtpSchema.parse(Object.fromEntries(formData))
  
  // 1. Validate OTP from Redis (fast path)
  const storedOtp = await redis.get(`otp:${email}`)
  
  if (storedOtp && storedOtp !== otp) {
    throw new Error('Invalid OTP')
  }
  
  // 2. Fallback: Validate from database
  const otpRecord = await db.oTPVerification.findFirst({
    where: {
      email,
      otp,
      type: 'VERIFY_EMAIL',
      isUsed: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  })
  
  if (!otpRecord) {
    throw new Error('Invalid or expired OTP')
  }
  
  // 3. Mark OTP as used
  await db.oTPVerification.update({
    where: { id: otpRecord.id },
    data: { isUsed: true },
  })
  
  // 4. Update user
  await db.user.update({
    where: { id: otpRecord.userId },
    data: { 
      emailVerified: true,
      status: 'ACTIVE',
    },
  })
  
  // 5. Clear Redis OTP
  await redis.del(`otp:${email}`)
  
  // 6. Create session
  const session = await authService.createSession(otpRecord.userId)
  
  return { success: true, session }
}
```

### 1.4 Login Flow

```typescript
// app/api/auth/login/action.ts
'use server'

import { loginSchema } from '@/lib/validators/auth.validator'
import { db } from '@/lib/db'
import { authService } from '@/services/auth.service'
import bcrypt from 'bcryptjs'

export async function login(formData: FormData) {
  const { email, password } = loginSchema.parse(Object.fromEntries(formData))
  
  // 1. Find user with role
  const user = await db.user.findUnique({
    where: { email },
    include: { role: true },
  })
  
  if (!user) {
    throw new Error('Invalid credentials')
  }
  
  // 2. Check password
  const isValid = await bcrypt.compare(password, user.password)
  
  if (!isValid) {
    // Log failed attempt
    await authService.logFailedLogin(user.id)
    throw new Error('Invalid credentials')
  }
  
  // 3. Check status
  if (user.status === 'SUSPENDED') {
    throw new Error('Account suspended')
  }
  
  if (user.status === 'PENDING') {
    throw new Error('Please verify your email first')
  }
  
  // 4. Create session
  const session = await authService.createSession(user.id)
  
  // 5. Log activity
  await db.activityLog.create({
    data: {
      action: 'LOGIN',
      resource: 'user',
      resourceId: user.id,
      userId: user.id,
    },
  })
  
  return { success: true, session }
}
```

### 1.5 Forgot Password Flow

```typescript
// app/api/auth/forgot-password/action.ts
'use server'

import { forgotPasswordSchema } from '@/lib/validators/auth.validator'
import { db } from '@/lib/db'
import { redis } from '@/lib/redis'
import { emailService } from '@/services/email.service'

export async function forgotPassword(formData: FormData) {
  const { email } = forgotPasswordSchema.parse(Object.fromEntries(formData))
  
  // 1. Check if user exists
  const user = await db.user.findUnique({
    where: { email },
  })
  
  // 2. Always return success (don't reveal if email exists)
  if (!user) {
    return { success: true, message: 'If email exists, reset link sent' }
  }
  
  // 3. Generate reset token
  const resetToken = crypto.randomUUID()
  
  // 4. Store in Redis with 1 hour expiry
  await redis.setex(
    `password-reset:${resetToken}`,
    3600,
    user.id
  )
  
  // 5. Send email
  const resetUrl = `${process.env.NEXT_PUBLIC_APP_URL}/auth/reset-password?token=${resetToken}`
  await emailService.sendPasswordReset(email, resetUrl)
  
  return { success: true, message: 'If email exists, reset link sent' }
}
```

### 1.6 Change Email Flow

```typescript
// app/api/auth/change-email/action.ts
'use server'

import { changeEmailSchema } from '@/lib/validators/auth.validator'
import { db } from '@/lib/db'
import { redis } from '@/lib/redis'
import { emailService } from '@/services/email.service'
import { getCurrentUser } from '@/services/auth.service'

export async function changeEmail(currentEmail: string, newEmail: string) {
  // 1. Verify current user
  const user = await getCurrentUser()
  
  if (!user || user.email !== currentEmail) {
    throw new Error('Unauthorized')
  }
  
  // 2. Check if new email is taken
  const existing = await db.user.findUnique({
    where: { email: newEmail },
  })
  
  if (existing) {
    throw new Error('Email already in use')
  }
  
  // 3. Generate OTP for new email
  const otp = Math.floor(100000 + Math.random() * 900000).toString()
  
  await db.oTPVerification.create({
    data: {
      userId: user.id,
      email: newEmail,
      otp,
      type: 'CHANGE_EMAIL',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    },
  })
  
  // 4. Send OTP to new email
  await emailService.sendOTP(newEmail, otp, 'Confirm Email Change')
  
  // 5. Store pending email in Redis
  await redis.setex(
    `email-change:${user.id}`,
    600, // 10 minutes
    newEmail
  )
  
  return { success: true, message: 'Verification sent to new email' }
}
```

---

## 2. SESSION MANAGEMENT

### 2.1 Session Storage (Redis)

```typescript
// lib/auth/session.ts
import { redis } from '@/lib/redis'

interface SessionData {
  userId: string
  email: string
  name: string
  role: string
  permissions: string[]
  createdAt: number
  expiresAt: number
}

const SESSION_TTL = 24 * 60 * 60 // 24 hours

export async function createSession(userId: string): Promise<string> {
  // Generate secure token
  const token = crypto.randomUUID() + ':' + crypto.randomUUID()
  
  // Get user data
  const user = await db.user.findUnique({
    where: { id: userId },
    include: { role: { include: { permissions: true } } },
  })
  
  if (!user) throw new Error('User not found')
  
  const sessionData: SessionData = {
    userId: user.id,
    email: user.email,
    name: user.name || '',
    role: user.role.type,
    permissions: user.role.permissions.map(p => `${p.resource}:${p.action}`),
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL * 1000,
  }
  
  // Store in Redis
  await redis.setex(`session:${token}`, SESSION_TTL, JSON.stringify(sessionData))
  
  // Also store reverse mapping
  await redis.setex(`session-user:${userId}:${token}`, SESSION_TTL, token)
  
  return token
}

export async function getSession(token: string): Promise<SessionData | null> {
  const data = await redis.get(`session:${token}`)
  
  if (!data) return null
  
  const session = JSON.parse(data) as SessionData
  
  // Check expiration
  if (session.expiresAt < Date.now()) {
    await destroySession(token)
    return null
  }
  
  return session
}

export async function destroySession(token: string): Promise<void> {
  const session = await getSession(token)
  
  if (session) {
    await redis.del(`session:${token}`)
    await redis.del(`session-user:${session.userId}:${token}`)
  }
}

export async function refreshSession(token: string): Promise<void> {
  const session = await getSession(token)
  
  if (session) {
    // Extend expiration
    await redis.expire(`session:${token}`, SESSION_TTL)
    await redis.expire(`session-user:${session.userId}:${token}`, SESSION_TTL)
  }
}
```

### 2.2 HTTP-Only Cookie

```typescript
// lib/auth/cookies.ts
import { cookies } from 'next/headers'

const SESSION_COOKIE_NAME = 'session_token'

export async function setSessionCookie(token: string): Promise<void> {
  cookies().set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60, // 24 hours
    path: '/',
  })
}

export async function getSessionCookie(): Promise<string | undefined> {
  return cookies().get(SESSION_COOKIE_NAME)?.value
}

export async function removeSessionCookie(): Promise<void> {
  cookies().delete(SESSION_COOKIE_NAME)
}
```

---

## 3. RBAC MIDDLEWARE

### 3.1 RBAC Middleware

```typescript
// middleware/rbac.middleware.ts
import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth/session'

// Permission matrix
const PERMISSIONS_MATRIX: Record<string, string[]> = {
  '/admin/users': ['user:read', 'user:create', 'user:update', 'user:delete'],
  '/admin/roles': ['role:read', 'role:create', 'role:update', 'role:delete'],
  '/admin/products': ['product:read', 'product:create', 'product:update', 'product:delete'],
  '/admin/orders': ['order:read', 'order:update'],
  '/admin/articles': ['article:read', 'article:create', 'article:update', 'article:delete'],
  '/admin/reports': ['report:read'],
  '/api/users': ['user:read', 'user:create', 'user:update', 'user:delete'],
  '/api/products': ['product:read', 'product:create', 'product:update', 'product:delete'],
  '/api/orders': ['order:read', 'order:create', 'order:update'],
  '/api/articles': ['article:read', 'article:create', 'article:update', 'article:delete'],
}

// Role permissions
const ROLE_PERMISSIONS: Record<string, string[]> = {
  SUPERADMIN: ['*'], // All permissions
  ADMIN: ['user:read', 'user:create', 'user:update', 'role:read', 'product:*', 'order:*', 'article:*', 'report:*'],
  MANAGER: ['product:*', 'order:read', 'order:update', 'article:*'],
  STAFF: ['product:read', 'product:create', 'order:read', 'article:read'],
  CUSTOMER: ['order:create', 'order:read'],
  GUEST: [],
}

export async function rbacMiddleware(request: NextRequest) {
  const token = request.cookies.get('session_token')?.value
  
  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  
  const session = await getSession(token)
  
  if (!session) {
    return NextResponse.json({ error: 'Session expired' }, { status: 401 })
  }
  
  const path = request.nextUrl.pathname
  
  // Get required permissions for this path
  const requiredPermissions = PERMISSIONS_MATRIX[path]
  
  if (!requiredPermissions || requiredPermissions.length === 0) {
    return NextResponse.next() // No permission required
  }
  
  // Get user permissions
  const userPermissions = ROLE_PERMISSIONS[session.role] || []
  
  // Superadmin has all permissions
  if (userPermissions.includes('*')) {
    return NextResponse.next()
  }
  
  // Check each required permission
  for (const perm of requiredPermissions) {
    const [resource, action] = perm.split(':')
    
    const hasPermission = userPermissions.some(p => {
      if (p === perm) return true
      if (p === `${resource}:*`) return true
      return false
    })
    
    if (!hasPermission) {
      return NextResponse.json(
        { error: 'Forbidden: Insufficient permissions' },
        { status: 403 }
      )
    }
  }
  
  // Attach user to request headers for downstream use
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', session.userId)
  requestHeaders.set('x-user-role', session.role)
  requestHeaders.set('x-user-permissions', JSON.stringify(userPermissions))
  
  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })
}
```

### 3.2 Role Guard Component

```typescript
// components/auth/role-guard.tsx
'use client'

import { useSession } from '@/hooks/use-auth'
import { ReactNode } from 'react'

interface RoleGuardProps {
  children: ReactNode
  allowedRoles: string[]
  fallback?: ReactNode
}

export function RoleGuard({ children, allowedRoles, fallback = null }: RoleGuardProps) {
  const { data: session, isLoading } = useSession()
  
  if (isLoading) {
    return <Skeleton />
  }
  
  if (!session) {
    return <>{fallback}</>
  }
  
  if (!allowedRoles.includes(session.role)) {
    return <>{fallback}</>
  }
  
  return <>{children}</>
}

// Usage examples:
// <RoleGuard allowedRoles={['SUPERADMIN', 'ADMIN']}>
//   <AdminPanel />
// </RoleGuard>

// <RoleGuard 
//   allowedRoles={['SUPERADMIN', 'ADMIN', 'MANAGER']}
//   fallback={<AccessDenied />}
// >
//   <ProductForm />
// </RoleGuard>
```

### 3.3 Permission Hook

```typescript
// hooks/use-permission.ts
import { useSession } from './use-auth'

export function usePermission() {
  const { data: session } = useSession()
  
  const hasPermission = (permission: string): boolean => {
    if (!session?.permissions) return false
    
    // Superadmin check
    if (session.permissions.includes('*')) return true
    
    const [resource, action] = permission.split(':')
    
    return session.permissions.some(p => {
      if (p === permission) return true
      if (p === `${resource}:*`) return true
      if (p === `${resource}:${action}`) return true
      return false
    })
  }
  
  const hasAnyPermission = (permissions: string[]): boolean => {
    return permissions.some(p => hasPermission(p))
  }
  
  const hasAllPermissions = (permissions: string[]): boolean => {
    return permissions.every(p => hasPermission(p))
  }
  
  const isSuperadmin = (): boolean => {
    return session?.role === 'SUPERADMIN'
  }
  
  const isAdmin = (): boolean => {
    return ['SUPERADMIN', 'ADMIN'].includes(session?.role || '')
  }
  
  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    isSuperadmin,
    isAdmin,
    permissions: session?.permissions || [],
    role: session?.role,
  }
}
```

---

## 4. SECURITY BEST PRACTICES

### 4.1 CSRF Protection

```typescript
// lib/auth/csrf.ts
import { cookies } from 'next/headers'

const CSRF_COOKIE_NAME = 'csrf_token'
const CSRF_HEADER_NAME = 'x-csrf-token'

export function generateCSRFToken(): string {
  return crypto.randomUUID()
}

export async function setCSRFCookie(): Promise<string> {
  const token = generateCSRFToken()
  
  cookies().set(CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60,
    path: '/',
  })
  
  return token
}

export async function validateCSRFToken(token: string): Promise<boolean> {
  const cookieToken = cookies().get(CSRF_COOKIE_NAME)?.value
  
  if (!cookieToken || !token) return false
  
  // Timing-safe comparison
  return crypto.timingSafeEqual(
    Buffer.from(cookieToken),
    Buffer.from(token)
  )
}

// CSRF middleware for API routes
export async function csrfMiddleware(request: Request) {
  // Skip for GET requests
  if (request.method === 'GET') return true
  
  const csrfToken = request.headers.get(CSRF_HEADER_NAME)
  
  if (!csrfToken) {
    throw new Error('CSRF token missing')
  }
  
  const isValid = await validateCSRFToken(csrfToken)
  
  if (!isValid) {
    throw new Error('Invalid CSRF token')
  }
  
  return true
}
```

### 4.2 Rate Limiting Middleware

```typescript
// middleware/rate-limit.middleware.ts
import { NextRequest, NextResponse } from 'next/server'
import { redis } from '@/lib/redis'

interface RateLimitConfig {
  windowMs: number
  maxRequests: number
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  '/api/auth/login': { windowMs: 15 * 60 * 1000, maxRequests: 5 },      // 5 attempts per 15 min
  '/api/auth/register': { windowMs: 60 * 60 * 1000, maxRequests: 3 },  // 3 per hour
  '/api/auth/forgot-password': { windowMs: 60 * 60 * 1000, maxRequests: 3 },
  '/api/otp/verify': { windowMs: 15 * 60 * 1000, maxRequests: 10 },
  '/api/contact': { windowMs: 60 * 1000, maxRequests: 10 },
}

export async function rateLimitMiddleware(request: NextRequest) {
  const path = request.nextUrl.pathname
  
  // Find matching rate limit config
  const config = Object.entries(RATE_LIMITS).find(([pattern]) => 
    path.startsWith(pattern)
  )
  
  if (!config) {
    return NextResponse.next() // No rate limit for this path
  }
  
  const [, { windowMs, maxRequests }] = config
  
  // Get client identifier (IP or user ID if logged in)
  const identifier = request.headers.get('x-forwarded-for')?.split(',')[0] 
    || request.ip 
    || 'unknown'
  
  const key = `rate:${identifier}:${path}`
  
  // Get current count
  const current = await redis.get(key)
  
  if (current && parseInt(current) >= maxRequests) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { status: 429, headers: { 'Retry-After': String(Math.ceil(windowMs / 1000)) } }
    )
  }
  
  // Increment counter
  const ttl = Math.ceil(windowMs / 1000)
  
  if (current) {
    await redis.incr(key)
  } else {
    await redis.setex(key, ttl, '1')
  }
  
  // Add rate limit headers
  const response = NextResponse.next()
  response.headers.set('X-RateLimit-Limit', String(maxRequests))
  response.headers.set('X-RateLimit-Remaining', String(maxRequests - (parseInt(current) || 0) - 1))
  response.headers.set('X-RateLimit-Reset', String(Date.now() + windowMs))
  
  return response
}
```

### 4.3 Session Validation Flow

```typescript
// services/auth.service.ts
import { db } from '@/lib/db'
import { getSession, createSession, destroySession } from '@/lib/auth/session'
import { cookies } from 'next/headers'

export async function getCurrentUser() {
  const token = cookies().get('session_token')?.value
  
  if (!token) return null
  
  const session = await getSession(token)
  
  if (!session) return null
  
  // Optionally refresh session
  await refreshSession(token)
  
  return {
    id: session.userId,
    email: session.email,
    name: session.name,
    role: session.role,
    permissions: session.permissions,
  }
}

export async function requireAuth() {
  const user = await getCurrentUser()
  
  if (!user) {
    throw new Error('Authentication required')
  }
  
  return user
}

export async function requireRole(...roles: string[]) {
  const user = await requireAuth()
  
  if (!roles.includes(user.role)) {
    throw new Error('Insufficient permissions')
  }
  
  return user
}

export async function logout() {
  const token = cookies().get('session_token')?.value
  
  if (token) {
    await destroySession(token)
    cookies().delete('session_token')
  }
  
  return { success: true }
}

export async function logFailedLogin(userId: string) {
  await db.activityLog.create({
    data: {
      action: 'LOGIN_FAILED',
      resource: 'user',
      resourceId: userId,
      userId,
    },
  })
}
```

---

## 5. AUTH VALIDATORS (ZOD)

```typescript
// lib/validators/auth.validator.ts
import { z } from 'zod'

export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  name: z.string().min(2, 'Name must be at least 2 characters'),
  phone: z.string().optional(),
})

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

export const verifyOtpSchema = z.object({
  email: z.string().email('Invalid email address'),
  otp: z.string().length(6, 'OTP must be 6 digits'),
})

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
})

export const resetPasswordSchema = z.object({
  token: z.string().uuid(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
})

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  confirmNewPassword: z.string(),
}).refine(data => data.newPassword === data.confirmNewPassword, {
  message: 'Passwords do not match',
  path: ['confirmNewPassword'],
})
```

---

## 6. SUMMARY

| Feature | Implementation |
|---------|----------------|
| Password Hashing | bcrypt (12 rounds) |
| Session Storage | Redis with 24h TTL |
| Session Cookie | HTTP-only, Secure, SameSite |
| OTP Storage | Redis (5min) + DB fallback |
| CSRF Protection | Double-submit cookie pattern |
| Rate Limiting | Redis per-IP, per-endpoint |
| RBAC | Middleware + Hook + Component |
| Superadmin | Wildcard permission (*) |

---

*Next Step: STEP 4 - Redis Caching Strategy*
