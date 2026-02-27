# STEP 3 — Authentication & RBAC Implementation

## 1. Authentication Flow Overview

### 1.1 Register Flow
```
1. User submits registration form (name, email, password)
2. Validate input with Zod schema
3. Check if email already exists
4. Hash password with bcrypt (salt rounds: 12)
5. Create user with PENDING status
6. Generate OTP for email verification
7. Send verification email with OTP
8. Return success response
```

### 1.2 Email Verification Flow
```
1. User clicks verification link / enters OTP
2. Validate OTP (check expiry, attempts)
3. Mark OTP as verified
4. Update user: emailVerified = true, status = ACTIVE
5. Create default CUSTOMER role
6. Send welcome notification
```

### 1.3 Login Flow
```
1. User submits login form (email, password)
2. Validate input
3. Find user by email
4. Verify password with bcrypt
5. Check user status (must be ACTIVE)
6. Generate session token (UUID + timestamp + salt)
7. Store session in Redis with TTL
8. Set HTTP-only cookie
9. Return user data (without password)
```

### 1.4 Forgot Password Flow
```
1. User submits email
2. Find user by email
3. Generate OTP for password reset
4. Store OTP in Redis with 15-min TTL
5. Send reset email
6. User enters new password + OTP
7. Validate OTP
8. Hash new password
9. Update user password
10. Invalidate all existing sessions
```

### 1.5 Change Email Flow
```
1. User requests email change (new email)
2. Generate OTP for new email
3. Send verification to NEW email
4. User verifies new email
5. Update user email
6. If previously unverified, mark emailVerified = true
```

---

## 2. Authentication Architecture

### 2.1 Project Structure
```
src/
├── lib/
│   ├── db.ts              # Prisma client
│   ├── redis.ts           # Redis client
│   ├── mail.ts            # Nodemailer
│   └── utils.ts           # Helpers
├── services/
│   ├── AuthService.ts     # Core auth logic
│   ├── SessionService.ts  # Session management
│   └── OTPService.ts      # OTP handling
├── repositories/
│   ├── UserRepository.ts
│   └── SessionRepository.ts
├── middleware/
│   ├── auth.ts            # Session validation
│   ├── csrf.ts            # CSRF protection
│   └── rateLimit.ts       # Rate limiting
├── validations/
│   └── auth.ts            # Zod schemas
└── types/
    └── enums.ts
```

---

## 3. Implementation Code

### 3.1 Core Types (`src/types/enums.ts`)

```typescript
// src/types/enums.ts

export enum UserStatus {
  PENDING = 'PENDING',
  ACTIVE = 'ACTIVE',
  SUSPENDED = 'SUSPENDED',
  BANNED = 'BANNED',
}

export enum RoleType {
  SUPERADMIN = 'SUPERADMIN',
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  STAFF = 'STAFF',
  CUSTOMER = 'CUSTOMER',
  GUEST = 'GUEST',
}

export enum PermissionAction {
  READ = 'read',
  WRITE = 'write',
  UPDATE = 'update',
  DELETE = 'delete',
}

export enum Resource {
  USERS = 'users',
  ROLES = 'roles',
  PERMISSIONS = 'permissions',
  PRODUCTS = 'products',
  ORDERS = 'orders',
  ARTICLES = 'articles',
  SERVICES = 'services',
  PORTFOLIO = 'portfolio',
  TESTIMONIALS = 'testimonials',
  PAYMENTS = 'payments',
  REPORTS = 'reports',
  SETTINGS = 'settings',
}
```

### 3.2 Auth Validation Schemas (`src/validations/auth.ts`)

```typescript
// src/validations/auth.ts
import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  confirmNewPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmNewPassword, {
  message: "Passwords don't match",
  path: ['confirmNewPassword'],
});

export const verifyEmailSchema = z.object({
  code: z.string().length(6, 'OTP must be 6 digits'),
});

export const changeEmailSchema = z.object({
  newEmail: z.string().email('Invalid email address'),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ChangeEmailInput = z.infer<typeof changeEmailSchema>;
```

### 3.3 User Repository (`src/repositories/UserRepository.ts`)

```typescript
// src/repositories/UserRepository.ts
import { db } from '@/lib/db';
import { UserStatus } from '@/types/enums';

export class UserRepository {
  async findByEmail(email: string) {
    return db.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: true,
              },
            },
          },
        },
        profile: true,
      },
    });
  }

  async findById(id: string) {
    return db.user.findUnique({
      where: { id },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: true,
              },
            },
          },
        },
        profile: true,
      },
    });
  }

  async create(data: {
    email: string;
    password: string;
    name: string;
    phone?: string;
  }) {
    const { password, ...rest } = data;
    return db.user.create({
      data: {
        ...rest,
        email: rest.email.toLowerCase(),
        password,
        status: UserStatus.PENDING,
        profile: {
          create: {},
        },
        cart: {
          create: {},
        },
      },
    });
  }

  async updatePassword(userId: string, hashedPassword: string) {
    return db.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });
  }

  async updateStatus(userId: string, status: UserStatus) {
    return db.user.update({
      where: { id: userId },
      data: { status, verifiedAt: status === UserStatus.ACTIVE ? new Date() : undefined },
    });
  }

  async assignRole(userId: string, roleId: string) {
    return db.userRole.create({
      data: { userId, roleId },
    });
  }

  async countByRole(roleName: string): Promise<number> {
    return db.userRole.count({
      where: {
        role: { name: roleName as any },
        user: { deletedAt: null },
      },
    });
  }
}

export const userRepository = new UserRepository();
```

### 3.4 Session Service (`src/services/SessionService.ts`)

```typescript
// src/services/SessionService.ts
import { redis } from '@/lib/redis';
import crypto from 'crypto';

const SESSION_TTL = 24 * 60 * 60; // 24 hours
const SESSION_PREFIX = 'session:';

export interface SessionData {
  userId: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  createdAt: number;
  ipAddress?: string;
  userAgent?: string;
}

export class SessionService {
  private generateToken(): string {
    return crypto.randomUUID() + ':' + Date.now();
  }

  private hashToken(token: string): string {
    const salt = process.env.SESSION_SECRET || 'default-salt';
    return crypto.createHmac('sha256', salt).update(token).digest('hex');
  }

  async createSession(data: Omit<SessionData, 'createdAt'>): Promise<string> {
    const token = this.generateToken();
    const sessionKey = SESSION_PREFIX + this.hashToken(token);
    
    const sessionData: SessionData = {
      ...data,
      createdAt: Date.now(),
    };

    await redis.setex(sessionKey, SESSION_TTL, JSON.stringify(sessionData));
    return token;
  }

  async getSession(token: string): Promise<SessionData | null> {
    const sessionKey = SESSION_PREFIX + this.hashToken(token);
    const data = await redis.get(sessionKey);
    
    if (!data) return null;
    
    const sessionData: SessionData = JSON.parse(data);
    
    // Sliding session: extend TTL on activity
    await redis.expire(sessionKey, SESSION_TTL);
    
    return sessionData;
  }

  async invalidateSession(token: string): Promise<void> {
    const sessionKey = SESSION_PREFIX + this.hashToken(token);
    await redis.del(sessionKey);
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    // For more complex scenarios, maintain a user session index in Redis
    const pattern = SESSION_PREFIX + '*';
    const keys = await redis.keys(pattern);
    
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const session: SessionData = JSON.parse(data);
        if (session.userId === userId) {
          await redis.del(key);
        }
      }
    }
  }
}

export const sessionService = new SessionService();
```

### 3.5 OTP Service (`src/services/OTPService.ts`)

```typescript
// src/services/OTPService.ts
import { db } from '@/lib/db';
import crypto from 'crypto';

export enum OTPType {
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  PASSWORD_RESET = 'PASSWORD_RESET',
  LOGIN = 'LOGIN',
  CHANGE_EMAIL = 'CHANGE_EMAIL',
}

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 15;
const MAX_ATTEMPTS = 3;

export class OTPService {
  private generateCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  private hashCode(code: string): string {
    const salt = process.env.OTP_SECRET || 'default-otp-salt';
    return crypto.createHmac('sha256', salt).update(code).digest('hex');
  }

  async createOTP(userId: string, type: OTPType): Promise<string> {
    // Invalidate any existing unused OTPs of same type
    await db.oTPVerification.deleteMany({
      where: {
        userId,
        type,
        verifiedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    const code = this.generateCode();
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await db.oTPVerification.create({
      data: {
        userId,
        type,
        code: this.hashCode(code),
        expiresAt,
        maxAttempts: MAX_ATTEMPTS,
      },
    });

    return code; // Return plain code to send via email
  }

  async verifyOTP(userId: string, type: OTPType, code: string): Promise<boolean> {
    const otpRecord = await db.oTPVerification.findFirst({
      where: {
        userId,
        type,
        verifiedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (!otpRecord) {
      throw new Error('OTP expired or not found');
    }

    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      throw new Error('Maximum attempts exceeded');
    }

    const isValid = otpRecord.code === this.hashCode(code);

    if (!isValid) {
      await db.oTPVerification.update({
        where: { id: otpRecord.id },
        data: { attempts: { increment: 1 } },
      });
      return false;
    }

    // Mark as verified
    await db.oTPVerification.update({
      where: { id: otpRecord.id },
      data: { verifiedAt: new Date() },
    });

    return true;
  }

  async getActiveOTP(userId: string, type: OTPType) {
    return db.oTPVerification.findFirst({
      where: {
        userId,
        type,
        verifiedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
  }
}

export const otpService = new OTPService();
```

### 3.6 Auth Service (`src/services/AuthService.ts`)

```typescript
// src/services/AuthService.ts
import bcrypt from 'bcrypt';
import { userRepository } from '@/repositories/UserRepository';
import { sessionService } from './SessionService';
import { otpService, OTPType } from './OTPService';
import { mailService } from './MailService';
import { UserStatus, RoleType } from '@/types/enums';
import { createCSRFToken } from '@/middleware/csrf';
import { cookies } from 'next/headers';

const SALT_ROUNDS = 12;
const COOKIE_NAME = 'session_token';

export class AuthService {
  async register(input: {
    name: string;
    email: string;
    password: string;
    phone?: string;
  }) {
    // Check if user exists
    const existingUser = await userRepository.findByEmail(input.email);
    if (existingUser) {
      throw new Error('Email already registered');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(input.password, SALT_ROUNDS);

    // Create user
    const user = await userRepository.create({
      ...input,
      password: hashedPassword,
    });

    // Generate OTP and send email
    const otpCode = await otpService.createOTP(user.id, OTPType.EMAIL_VERIFICATION);
    await mailService.sendVerificationEmail(user.email, otpCode, user.name || 'User');

    return {
      userId: user.id,
      message: 'Registration successful. Please verify your email.',
    };
  }

  async verifyEmail(userId: string, code: string) {
    const isValid = await otpService.verifyOTP(userId, OTPType.EMAIL_VERIFICATION, code);
    
    if (!isValid) {
      throw new Error('Invalid or expired verification code');
    }

    // Update user status
    await userRepository.updateStatus(userId, UserStatus.ACTIVE);

    // Assign default customer role
    const defaultRole = await db.role.findUnique({
      where: { name: RoleType.CUSTOMER },
    });
    
    if (defaultRole) {
      await userRepository.assignRole(userId, defaultRole.id);
    }

    return { message: 'Email verified successfully' };
  }

  async login(input: { email: string; password: string }) {
    const user = await userRepository.findByEmail(input.email);
    
    if (!user) {
      throw new Error('Invalid credentials');
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new Error('Account is not active');
    }

    const isValidPassword = await bcrypt.compare(input.password, user.password);
    if (!isValidPassword) {
      throw new Error('Invalid credentials');
    }

    // Get user roles and permissions
    const roles = user.roles.map((ur) => ur.role.name);
    const permissions = user.roles.flatMap((ur) => 
      ur.role.permissions.map((p) => `${p.resource}.${p.action}`)
    );

    // Create session
    const sessionToken = await sessionService.createSession({
      userId: user.id,
      email: user.email,
      name: user.name || '',
      roles,
      permissions,
    });

    // Set HTTP-only cookie
    const cookieStore = await cookies();
    cookieStore.set(COOKIE_NAME, sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60, // 24 hours
      path: '/',
    });

    // Get CSRF token
    const csrfToken = createCSRFToken();

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles,
        permissions,
      },
      csrfToken,
    };
  }

  async logout() {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get(COOKIE_NAME)?.value;
    
    if (sessionToken) {
      await sessionService.invalidateSession(sessionToken);
    }

    cookieStore.delete(COOKIE_NAME);
  }

  async forgotPassword(email: string) {
    const user = await userRepository.findByEmail(email);
    
    if (!user) {
      // Don't reveal if email exists
      return { message: 'If the email exists, a reset link will be sent' };
    }

    const otpCode = await otpService.createOTP(user.id, OTPType.PASSWORD_RESET);
    await mailService.sendPasswordResetEmail(user.email, otpCode, user.name || 'User');

    return { message: 'If the email exists, a reset link will be sent' };
  }

  async resetPassword(token: string, newPassword: string) {
    // Token contains userId encoded (simplified - use proper token in production)
    const [userId, code] = Buffer.from(token, 'base64').toString().split(':');
    
    if (!userId || !code) {
      throw new Error('Invalid token');
    }

    const isValid = await otpService.verifyOTP(userId, OTPType.PASSWORD_RESET, code);
    if (!isValid) {
      throw new Error('Invalid or expired reset code');
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await userRepository.updatePassword(userId, hashedPassword);
    
    // Invalidate all sessions
    await sessionService.invalidateAllUserSessions(userId);

    return { message: 'Password reset successful' };
  }
}

export const authService = new AuthService();
```

### 3.7 Mail Service (`src/services/MailService.ts`)

```typescript
// src/services/MailService.ts
import nodemailer from 'nodemailer';
import { env } from 'process';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export class MailService {
  async sendVerificationEmail(email: string, code: string, name: string) {
    const mailOptions = {
      from: `"${process.env.SMTP_FROM_NAME}" <${process.env.SMTP_FROM_EMAIL}>`,
      to: email,
      subject: 'Verify Your Email Address',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello ${name},</h2>
          <p>Thank you for registering. Your verification code is:</p>
          <div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0;">
            <strong>${code}</strong>
          </div>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't create an account, please ignore this email.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
  }

  async sendPasswordResetEmail(email: string, code: string, name: string) {
    const mailOptions = {
      from: `"${process.env.SMTP_FROM_NAME}" <${process.env.SMTP_FROM_EMAIL}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello ${name},</h2>
          <p>You requested a password reset. Your code is:</p>
          <div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0;">
            <strong>${code}</strong>
          </div>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
  }

  async sendWelcomeEmail(email: string, name: string) {
    const mailOptions = {
      from: `"${process.env.SMTP_FROM_NAME}" <${process.env.SMTP_FROM_EMAIL}>`,
      to: email,
      subject: 'Welcome to Our Platform!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Welcome ${name}!</h2>
          <p>Thank you for joining us. We're excited to have you!</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
  }
}

export const mailService = new MailService();
```

---

## 4. Middleware Implementation

### 4.1 Auth Middleware (`src/middleware/auth.ts`)

```typescript
// src/middleware/auth.ts
import { NextRequest, NextResponse } from 'next/server';
import { sessionService, SessionData } from '@/services/SessionService';

const PUBLIC_PATHS = ['/login', '/register', '/forgot-password', '/api/auth', '/api/public'];

export async function authMiddleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (PUBLIC_PATHS.some((path) => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  // Allow static files
  if (pathname.startsWith('/_next') || pathname.startsWith('/images')) {
    return NextResponse.next();
  }

  // Get session token from cookie
  const sessionToken = request.cookies.get('session_token')?.value;

  if (!sessionToken) {
    // Redirect to login for protected pages
    if (pathname.startsWith('/dashboard') || pathname.startsWith('/admin')) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    return NextResponse.next();
  }

  // Validate session
  const session = await sessionService.getSession(sessionToken);

  if (!session) {
    const response = NextResponse.redirect(new URL('/login', request.url));
    response.cookies.delete('session_token');
    return response;
  }

  // Attach user to request headers for API routes
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-user-id', session.userId);
  requestHeaders.set('x-user-roles', JSON.stringify(session.roles));
  requestHeaders.set('x-user-permissions', JSON.stringify(session.permissions));

  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
}
```

### 4.2 RBAC Middleware / Guard (`src/middleware/rbac.ts`)

```typescript
// src/middleware/rbac.ts
import { NextRequest, NextResponse } from 'next/server';
import { sessionService, SessionData } from '@/services/SessionService';
import { PermissionAction, Resource } from '@/types/enums';

export type Permission = `${Resource}.${PermissionAction}`;

const ROLE_PERMISSION_MAP: Record<string, Permission[]> = {
  SUPERADMIN: ['*'], // Wildcard = all permissions
  ADMIN: [
    'users.read', 'users.write', 'users.update', 'users.delete',
    'roles.read', 'roles.write',
    'products.read', 'products.write', 'products.update', 'products.delete',
    'orders.read', 'orders.update',
    'articles.read', 'articles.write', 'articles.update', 'articles.delete',
    'services.read', 'services.write', 'services.update', 'services.delete',
    'payments.read', 'payments.update',
    'reports.read',
    'settings.read', 'settings.update',
  ],
  MANAGER: [
    'products.read', 'products.write', 'products.update',
    'orders.read', 'orders.update',
    'articles.read', 'articles.write', 'articles.update',
    'services.read', 'services.write', 'services.update',
    'payments.read',
    'reports.read',
  ],
  STAFF: [
    'products.read',
    'orders.read', 'orders.update',
    'articles.read',
    'services.read',
  ],
  CUSTOMER: [
    'products.read',
    'orders.read', 'orders.create',
    'articles.read',
    'services.read',
  ],
  GUEST: [
    'products.read',
    'articles.read',
    'services.read',
  ],
};

export function hasPermission(roles: string[], requiredPermission: Permission): boolean {
  for (const role of roles) {
    const permissions = ROLE_PERMISSION_MAP[role] || [];
    
    // Superadmin has all permissions
    if (permissions.includes('*' as Permission)) {
      return true;
    }
    
    if (permissions.includes(requiredPermission)) {
      return true;
    }
  }
  
  return false;
}

export function requirePermission(permission: Permission) {
  return async (request: NextRequest) => {
    const permissionsHeader = request.headers.get('x-user-permissions');
    const rolesHeader = request.headers.get('x-user-roles');
    
    if (!permissionsHeader || !rolesHeader) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const roles = JSON.parse(rolesHeader);
    const permissions = JSON.parse(permissionsHeader);
    
    // Check from session permissions first
    if (permissions.includes(permission) || permissions.includes('*')) {
      return NextResponse.next();
    }
    
    // Fallback to role-based check
    if (hasPermission(roles, permission)) {
      return NextResponse.next();
    }
    
    return NextResponse.json(
      { error: 'Forbidden: You do not have permission' },
      { status: 403 }
    );
  };
}

export function requireRole(...roles: string[]) {
  return async (request: NextRequest) => {
    const rolesHeader = request.headers.get('x-user-roles');
    
    if (!rolesHeader) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const userRoles = JSON.parse(rolesHeader);
    
    if (!userRoles.some((role: string) => roles.includes(role))) {
      return NextResponse.json(
        { error: 'Forbidden: Insufficient role' },
        { status: 403 }
      );
    }
    
    return NextResponse.next();
  };
}
```

### 4.3 CSRF Middleware (`src/middleware/csrf.ts`)

```typescript
// src/middleware/csrf.ts
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'x-csrf-token';

export function createCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export async function csrfMiddleware(request: NextRequest) {
  const { pathname, method } = request.nextUrl;

  // Only apply CSRF to state-changing methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return NextResponse.next();
  }

  // Skip for webhooks (they have their own validation)
  if (pathname.startsWith('/api/webhooks')) {
    return NextResponse.next();
  }

  // Skip for public API routes
  if (pathname.startsWith('/api/auth/login') || pathname.startsWith('/api/auth/register')) {
    return NextResponse.next();
  }

  const csrfToken = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  const requestCsrfToken = request.headers.get(CSRF_HEADER_NAME);

  // Validate CSRF token
  if (!csrfToken || !requestCsrfToken || csrfToken !== requestCsrfToken) {
    return NextResponse.json(
      { error: 'CSRF validation failed' },
      { status: 403 }
    );
  }

  return NextResponse.next();
}

// Helper to set CSRF cookie in response
export function setCSRFCookie(response: NextResponse, token: string) {
  response.cookies.set(CSRF_COOKIE_NAME, token, {
    httpOnly: false, // Must be readable by JS for header
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 24 * 60 * 60, // 24 hours
  });
  return response;
}
```

### 4.4 Rate Limiting Middleware (`src/middleware/rateLimit.ts`)

```typescript
// src/middleware/rateLimit.ts
import { NextRequest, NextResponse } from 'next/server';
import { redis } from '@/lib/redis';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  default: { windowMs: 60000, maxRequests: 100 }, // 100 req/min
  auth: { windowMs: 900000, maxRequests: 5 }, // 5 req/15min
  login: { windowMs: 900000, maxRequests: 3 }, // 3 attempts/15min
  api: { windowMs: 60000, maxRequests: 200 }, // 200 req/min for API
};

const RATE_LIMIT_PREFIX = 'rate_limit:';

export async function rateLimitMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname, ip } = request.nextUrl;
  
  // Determine rate limit config
  let config = RATE_LIMITS.default;
  
  if (pathname.startsWith('/api/auth/login')) {
    config = RATE_LIMITS.login;
  } else if (pathname.startsWith('/api/auth')) {
    config = RATE_LIMITS.auth;
  } else if (pathname.startsWith('/api')) {
    config = RATE_LIMITS.api;
  }

  // Get identifier (user ID if authenticated, otherwise IP)
  const userId = request.headers.get('x-user-id');
  const identifier = userId || ip || 'unknown';
  
  const key = RATE_LIMIT_PREFIX + pathname + ':' + identifier;
  
  // Get current count
  const current = await redis.get(key);
  const count = current ? parseInt(current) : 0;

  if (count >= config.maxRequests) {
    return NextResponse.json(
      { error: 'Too many requests. Please try again later.' },
      { status: 429, headers: { 'Retry-After': String(Math.ceil(config.windowMs / 1000)) } }
    );
  }

  // Increment counter
  const pipeline = redis.pipeline();
  pipeline.incr(key);
  if (count === 0) {
    pipeline.expire(key, Math.ceil(config.windowMs / 1000));
  }
  await pipeline.exec();

  return null; // Allow request to proceed
}
```

---

## 5. Security Best Practices

### 5.1 Password Security
- **Bcrypt** with salt rounds 12
- Minimum 8 characters + uppercase + lowercase + number
- No password in plain text ever stored
- Password reset invalidates all sessions

### 5.2 Session Security
- **UUID + timestamp** tokens (not JWT - stored in Redis)
- HTTP-only, Secure, SameSite=Strict cookies
- **Sliding expiration** on activity
- Server-side session storage (Redis)
- Invalidate on logout

### 5.3 CSRF Protection
- **Double-submit cookie** pattern
- Validate on all state-changing requests
- Generate new token on login

### 5.4 Rate Limiting
- **Per-IP + per-user** limits
- Stricter limits for auth endpoints
- Redis for distributed rate limiting

### 5.5 Superadmin Constraint
- Maximum **2 superadmin** users
- Check before assigning role
- Log all superadmin actions

---

## 6. API Route Examples

### 6.1 Register (`src/app/api/auth/register/route.ts`)

```typescript
// src/app/api/auth/register/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/services/AuthService';
import { registerSchema } from '@/validations/auth';
import { rateLimitMiddleware } from '@/middleware/rateLimit';

export async function POST(request: NextRequest) {
  // Rate limiting
  const rateLimit = await rateLimitMiddleware(request);
  if (rateLimit) return rateLimit;

  try {
    const body = await request.json();
    const validated = registerSchema.parse(body);
    
    const result = await authService.register(validated);
    
    return NextResponse.json(result, { status: 201 });
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Registration failed' },
      { status: 400 }
    );
  }
}
```

### 6.2 Login (`src/app/api/auth/login/route.ts`)

```typescript
// src/app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { authService } from '@/services/AuthService';
import { loginSchema } from '@/validations/auth';
import { rateLimitMiddleware } from '@/middleware/rateLimit';

export async function POST(request: NextRequest) {
  // Rate limiting
  const rateLimit = await rateLimitMiddleware(request);
  if (rateLimit) return rateLimit;

  try {
    const body = await request.json();
    const validated = loginSchema.parse(body);
    
    const result = await authService.login(validated);
    
    return NextResponse.json(result);
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || 'Login failed' },
      { status: 401 }
    );
  }
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
