# STEP 1: System Architecture & Folder Structure

## Enterprise CMS Company Profile - Architecture Design

---

## 1. HIGH-LEVEL SYSTEM ARCHITECTURE EXPLANATION

### Architecture Diagram (Conceptual)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER (Next.js)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │   Web App   │  │  Dashboard  │  │   Public    │  │   Mobile    │       │
│  │   (Admin)   │  │   (Admin)   │  │   (CMS)     │  │  (PWA)      │       │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │
└─────────┼────────────────┼────────────────┼────────────────┼──────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        API GATEWAY / MIDDLEWARE                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │    Rate     │  │     CSRF    │  │  Session    │  │   CORS &    │       │
│  │  Limiter    │  │  Middleware │  │  Validator │  │   Headers   │       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER (Next.js)                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Server Actions / API Routes                    │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐           │   │
│  │  │  Auth     │  │  CMS      │  │  Payment  │  │  Report   │           │   │
│  │  │  Module  │  │  Module   │  │  Module   │  │  Module   │           │   │
│  │  └───────────┘ └───────────┘ └───────────┘ └───────────┘           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SERVICE LAYER                                       │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │  AuthService  │  │  CMSService   │  │ PaymentService│  │ ReportService │   │
│  │  - login      │  │  - articles   │  │  - create     │  │  - generate   │   │
│  │  - register   │  │  - products   │  │  - webhook    │  │  - export     │   │
│  │  - otp        │  │  - services   │  │  - status     │  │  - summary    │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │ CacheService  │  │EmailService   │  │FileService    │  │NotifyService  │   │
│  │  - get/set    │  │  - send       │  │  - upload     │  │  - push       │   │
│  │  - invalidate │  │  - templates  │  │  - validate   │  │  - broadcast  │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       REPOSITORY LAYER                                      │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │ UserRepository│ │ProductReposity│ │OrderRepository│ │PaymentRepo    │   │
│  │ - findByEmail │ │ - findAll     │ │ - findById    │ │ - findByOrder │   │
│  │ - create      │ │ - search     │ │ - create      │ │ - update      │   │
│  │ - update      │ │ - paginate   │ │ - update      │ │ - webhook     │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATABASE LAYER                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     PostgreSQL (Primary DB)                         │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │   │
│  │  │  Users  │ │ Orders  │ │Articles │ │Products │ │Payments │        │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CACHE LAYER (Redis)                                 │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │    Session    │  │    Cart       │  │  Product      │  │  Dashboard    │   │
│  │    Store      │  │    Cache      │  │  Catalog      │  │  Summary      │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐                   │
│  │    OTP        │  │  Rate Limit   │  │  Search       │                   │
│  │    Store      │  │    Counter     │  │  Cache        │                   │
│  └───────────────┘ └───────────────┘ └───────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       EXTERNAL SERVICES                                     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   │
│  │   Midtrans    │  │  Nodemailer   │  │   S3/Cloud    │  │   Analytics   │   │
│  │  (Payment)    │  │   (Email)     │  │  (Storage)    │  │   (Stats)     │   │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1.1 FRONTEND LAYER

**Technology:** Next.js 14+ (App Router), TypeScript, React 18

**Components:**
- **Admin Dashboard** (`/admin/*`) - Full CRUD operations, analytics, user management
- **Public CMS** (`/*`) - Company profile, articles, products, services, portfolio
- **Authentication** (`/auth/*`) - Login, register, forgot password, OTP verification

**Key Features:**
- Server-Side Rendering (SSR) for public pages
- Client-side rendering for interactive dashboards
- Server Actions for form submissions
- Optimistic UI updates with React mutations

---

## 1.2 BACKEND LAYER

**Technology:** Next.js API Routes + Server Actions

**Modules:**
| Module | Responsibility |
|--------|----------------|
| `auth` | Login, register, OTP, session management |
| `users` | User CRUD, profile management |
| `roles` | Role & permission management |
| `cms` | Articles, products, services, portfolio |
| `orders` | Order management, cart |
| `payments` | Midtrans integration, webhook handling |
| `reports` | Financial reports, CSV export |
| `notifications` | System notifications |
| `analytics` | Visitor tracking, statistics |

---

## 1.3 DATABASE LAYER

**Technology:** PostgreSQL 15+ with Prisma ORM

**Design Principles:**
- Normalized schema (3NF)
- Soft delete on all entities
- UUID primary keys
- Timestamps (`createdAt`, `updatedAt`)
- Audit trail via `ActivityLog`

---

## 1.4 CACHE LAYER

**Technology:** Redis (ioredis client)

**Caching Strategy:**
| Data Type | TTL | Invalidation |
|-----------|-----|--------------|
| Sessions | 24h | Logout, password change |
| Cart | 24h | Cart update, checkout |
| Product Catalog | 1h | Product CRUD, inventory change |
| Dashboard Summary | 5min | Any data change |
| OTP | 5min | Expiration |
| Search Results | 30min | Product/article change |
| Rate Limit | 1min | N/A |

---

## 1.5 PAYMENT GATEWAY INTEGRATION

**Provider:** Midtrans (Snap & Core API)

**Flow:**
1. User initiates checkout → Create order → Generate Midtrans token
2. Redirect to Midtrans payment page
3. User completes payment → Midtrans sends webhook
4. Server validates signature → Update order status → Generate financial report
5. Send notification to user

---

## 1.6 EMAIL SERVICE

**Technology:** Nodemailer with SMTP

**Transactional Emails:**
- Email verification (OTP)
- Welcome email
- Password reset
- Order confirmation
- Payment status update
- New order notification (admin)

---

## 1.7 SECURITY LAYER

**Implementations:**
- **Authentication:** Session-based with HTTP-only cookies
- **Authorization:** RBAC with role-permission matrix
- **CSRF:** Double-submit cookie pattern
- **Rate Limiting:** Redis-based per-IP, per-user
- **Input Validation:** Zod schemas
- **File Upload:** Type + size validation, malware scan recommendation
- **SQL Injection:** Prisma parameterized queries (built-in)
- **XSS:** Content sanitization, React auto-escaping
- **SSL/TLS:** Enforced in production

---

## 1.8 NOTIFICATION FEATURE

**Types:**
- **In-App:** Database-backed, real-time via polling/SSE
- **Email:** Nodemailer for critical alerts

**Triggers:**
| Event | Target | Channel |
|-------|--------|---------|
| New Order | Admin | In-App + Email |
| Payment Success | Customer | In-App + Email |
| Payment Failed | Customer | In-App + Email |
| New User Registered | Admin | In-App |
| Low Stock Alert | Admin | In-App + Email |
| System Alert | All Admins | In-App |

---

## 2. SCALABLE FOLDER STRUCTURE (Next.js App Router)

```
cms/
├── .env.example                    # Environment variables template
├── .gitignore
├── next.config.js                  # Next.js configuration
├── package.json
├── tsconfig.json
├── tailwind.config.ts              # Tailwind + shadcn/ui config
├── postcss.config.js
├── drizzle.config.ts               # If using Drizzle (optional)
├── prisma/
│   └── schema.prisma               # Database schema
├── public/
│   ├── images/                     # Static images
│   ├── fonts/
│   └── favicon.ico
├── src/
│   ├── app/                        # Next.js App Router
│   │   ├── (auth)/                 # Auth route group
│   │   │   ├── login/
│   │   │   ├── register/
│   │   │   └── forgot-password/
│   │   ├── (dashboard)/            # Protected dashboard
│   │   │   ├── layout.tsx          # Dashboard layout with sidebar
│   │   │   ├── dashboard/
│   │   │   ├── users/
│   │   │   ├── roles/
│   │   │   ├── products/
│   │   │   ├── orders/
│   │   │   ├── articles/
│   │   │   ├── services/
│   │   │   ├── portfolio/
│   │   │   ├── reports/
│   │   │   └── settings/
│   │   ├── (public)/               # Public CMS pages
│   │   │   ├── page.tsx            # Home /
│   │   │   ├── about/
│   │   │   ├── services/
│   │   │   ├── products/
│   │   │   ├── portfolio/
│   │   │   ├── articles/
│   │   │   └── contact/
│   │   ├── api/                    # API Routes (webhooks, external)
│   │   │   ├── auth/
│   │   │   ├── midtrans/
│   │   │   └── webhooks/
│   │   ├── layout.tsx              # Root layout
│   │   └── globals.css             # Global styles
│   │
│   ├── components/                 # Shared components
│   │   ├── ui/                     # shadcn/ui components
│   │   │   ├── button.tsx
│   │   │   ├── input.tsx
│   │   │   ├── card.tsx
│   │   │   ├── table.tsx
│   │   │   ├── dialog.tsx
│   │   │   ├── dropdown-menu.tsx
│   │   │   ├── form.tsx
│   │   │   ├── select.tsx
│   │   │   ├── checkbox.tsx
│   │   │   ├── switch.tsx
│   │   │   ├── badge.tsx
│   │   │   ├── avatar.tsx
│   │   │   ├── skeleton.tsx
│   │   │   ├── toast.tsx
│   │   │   └── ...
│   │   ├── layout/
│   │   │   ├── sidebar.tsx
│   │   │   ├── header.tsx
│   │   │   ├── footer.tsx
│   │   │   └── theme-provider.tsx
│   │   ├── data-table/             # Reusable data table
│   │   ├── charts/                 # Chart components
│   │   ├── forms/                  # Reusable form components
│   │   └── providers/              # Context providers
│   │
│   ├── modules/                    # Feature modules (domain-driven)
│   │   ├── auth/
│   │   │   ├── components/         # Auth-specific components
│   │   │   ├── hooks/              # Auth hooks
│   │   │   ├── types/              # TypeScript types
│   │   │   └── constants.ts
│   │   ├── users/
│   │   ├── roles/
│   │   ├── products/
│   │   ├── orders/
│   │   ├── articles/
│   │   ├── services/
│   │   ├── portfolio/
│   │   ├── payments/
│   │   ├── reports/
│   │   └── notifications/
│   │
│   ├── services/                   # Business logic layer
│   │   ├── auth.service.ts
│   │   ├── user.service.ts
│   │   ├── product.service.ts
│   │   ├── order.service.ts
│   │   ├── payment.service.ts
│   │   ├── email.service.ts
│   │   ├── cache.service.ts
│   │   ├── notification.service.ts
│   │   └── analytics.service.ts
│   │
│   ├── repositories/               # Data access layer
│   │   ├── user.repository.ts
│   │   ├── role.repository.ts
│   │   ├── product.repository.ts
│   │   ├── order.repository.ts
│   │   ├── article.repository.ts
│   │   └── payment.repository.ts
│   │
│   ├── lib/                        # Utilities & configurations
│   │   ├── db.ts                   # Prisma client instance
│   │   ├── redis.ts                # Redis client instance
│   │   ├── auth.ts                 # Auth utilities
│   │   ├── csrf.ts                 # CSRF utilities
│   │   ├── midtrans.ts             # Midtrans config
│   │   ├── email.ts                # Email config
│   │   ├── utils.ts                # General utilities
│   │   ├── constants.ts            # App constants
│   │   └── validators/             # Zod validators
│   │       ├── auth.validator.ts
│   │       ├── user.validator.ts
│   │       ├── product.validator.ts
│   │       └── order.validator.ts
│   │
│   ├── hooks/                      # Custom React hooks
│   │   ├── use-auth.ts
│   │   ├── use-cart.ts
│   │   ├── use-toast.ts
│   │   ├── use-theme.ts
│   │   └── use debounce.ts
│   │
│   ├── middleware/                 # Next.js middleware
│   │   ├── auth.middleware.ts
│   │   ├── rbac.middleware.ts
│   │   ├── rate-limit.middleware.ts
│   │   └── csrf.middleware.ts
│   │
│   ├── types/                      # Global TypeScript types
│   │   ├── next.d.ts               # Next.js types
│   │   ├── prisma.d.ts             # Prisma types
│   │   └── global.d.ts             # Global types
│   │
│   └── utils/                      # Helper functions
│       ├── format-currency.ts
│       ├── format-date.ts
│       ├── generate-slug.ts
│       ├── paginate.ts
│       └── csv-export.ts
│
└── scripts/                        # Utility scripts
    ├── db/
    │   ├── seed.ts
    │   └── migrate.ts
    ├── build.ts
    └── deploy.sh
```

---

## 3. MODULAR ARCHITECTURE SEPARATION

### 3.1 `modules/` - Domain-Driven Design

Each module is self-contained with:
- **Components:** Module-specific UI components
- **Hooks:** Module-specific React hooks
- **Types:** Module-specific TypeScript interfaces

```
modules/
└── products/
    ├── components/
    │   ├── product-card.tsx
    │   ├── product-form.tsx
    │   └── product-table.tsx
    ├── hooks/
    │   └── use-products.ts
    └── types/
        └── product.types.ts
```

### 3.2 `services/` - Business Logic

Pure functions handling business logic, independent of HTTP/DB:

```typescript
// services/product.service.ts
export class ProductService {
  async create(data: CreateProductDTO) {
    // Business logic validation
    // Cache invalidation
    // Event dispatch
  }
  
  async update(id: string, data: UpdateProductDTO) {
    // ...
  }
  
  async delete(id: string) {
    // Soft delete
    // Invalidate cache
  }
}
```

### 3.3 `repositories/` - Data Access

Abstraction over Prisma, handles all DB queries:

```typescript
// repositories/product.repository.ts
export class ProductRepository {
  async findAll(pagination: PaginationParams) {
    return prisma.product.findMany({
      skip: pagination.skip,
      take: pagination.limit,
      where: { deletedAt: null },
      include: { category: true, images: true }
    });
  }
  
  async findById(id: string) {
    return prisma.product.findUnique({ where: { id } });
  }
}
```

### 3.4 `lib/` - Core Utilities

- `db.ts` - Prisma singleton
- `redis.ts` - Redis client
- `validators/` - Zod schemas

### 3.5 `hooks/` - React Hooks

Custom hooks for reusable client logic:

```typescript
// hooks/use-auth.ts
export function useAuth() {
  const { data: session } = useSession();
  // ...
}
```

### 3.6 `middleware/` - Request Processing

Next.js middleware for:
- Authentication verification
- RBAC enforcement
- Rate limiting
- CSRF protection

### 3.7 `validations/` - Input Validation

Zod schemas for API/Form validation:

```typescript
// lib/validators/auth.validator.ts
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});
```

### 3.8 `types/` - TypeScript Definitions

Global types extending Prisma/Next.js:

```typescript
// types/global.d.ts
declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      email: string;
      role: string;
    }
  }
}
```

---

## 4. ARCHITECTURE EXPLANATIONS

### 4.1 HOW RBAC IS ENFORCED

```
┌─────────────────────────────────────────────────────────────┐
│                      RBAC FLOW                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Request ──▶ Middleware ──▶ Route Handler ──▶ Service      │
│                  │                                            │
│                  ▼                                            │
│           ┌──────────────┐                                    │
│           │ Check Role  │                                    │
│           └──────────────┘                                    │
│                  │                                            │
│          ┌──────┴──────┐                                      │
│          │             │                                      │
│      ┌───▼───┐    ┌────▼────┐                                │
│      │ Allow │    │ Deny    │                                │
│      └───┬───┘    └─────────┘                                │
│          │                                                   │
│          ▼                                                   │
│   ┌──────────────┐                                           │
│   │ Validate     │                                           │
│   │ Permission   │                                           │
│   └──────────────┘                                           │
│          │                                                   │
│          ▼                                                   │
│      403 / 401                                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**
1. **Database:** Role ↔ Permission many-to-many
2. **Middleware:** Extract user role from session
3. **Guard:** Check route permission against user role
4. **Component:** Hide/show UI based on permissions

### 4.2 HOW CACHING STRATEGY WORKS

```
┌─────────────────────────────────────────────────────────────┐
│                   CACHING FLOW                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Client Request ──▶ Check Redis Cache ──▶ Cache Hit?      │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │             │                          │
│               ┌────▼────┐   ┌────▼─────┐                    │
│               │   YES   │   │   NO     │                    │
│               └────┬────┘   └─────┬────┘                    │
│                    │             │                          │
│                    ▼             ▼                          │
│              Return Cache    Query DB                       │
│                    │             │                          │
│                    │             ▼                          │
│                    │        Store Cache                     │
│                    │             │                          │
│                    └──────┬──────┘                          │
│                           ▼                                  │
│                    Return Data                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Cache Key Convention:**
```
session:{sessionId}
cart:{userId}
product:{id}
product:list:{page}:{limit}:{filter}
dashboard:summary:{role}
search:{query}:{filters}
otp:{email}
rate:{ip}:{endpoint}
```

### 4.3 HOW TRANSACTIONS ARE HANDLED

**Prisma Transaction Usage:**

```typescript
// Service layer
async function createOrderWithPayment(userId: string, items: CartItem[]) {
  return prisma.$transaction(async (tx) => {
    // 1. Create order
    const order = await tx.order.create({
      data: { userId, status: 'PENDING', /* ... */ }
    });
    
    // 2. Create order items
    await tx.orderItem.createMany({
      data: items.map(item => ({ orderId: order.id, /* ... */ }))
    });
    
    // 3. Clear cart
    await tx.cart.deleteMany({ where: { userId } });
    
    // 4. Update inventory (optional)
    // If any fails, all roll back
    
    return order;
  });
}
```

**ACID Compliance:**
- **Atomicity:** All-or-nothing via `$transaction`
- **Consistency:** Foreign key constraints, triggers
- **Isolation:** Default Prisma isolation level
- **Durability:** PostgreSQL WAL

### 4.4 HOW WEBHOOK PAYMENT FLOWS WORK

```
┌─────────────────────────────────────────────────────────────┐
│                MIDTRANS WEBHOOK FLOW                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Midtrans │    │  Server  │    │ Database │              │
│  │  Payment │───▶│  Webhook │───▶│ Update   │              │
│  │  Gateway │    │  Handler │    │ Status   │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │                     │
│       │               ▼               │                     │
│       │        ┌──────────┐           │                     │
│       │        │ Validate │           │                     │
│       │        │ Signature│           │                     │
│       │        └──────────┘           │                     │
│       │               │               │                     │
│       │               ▼               │                     │
│       │        ┌──────────┐           │                     │
│       │        │  Find    │           │                     │
│       │        │  Order   │           │                     │
│       │        └──────────┘           │                     │
│       │               │               │                     │
│       │               ▼               │                     │
│       │        ┌──────────┐           │                     │
│       │        │ Update   │───────────▶│                     │
│       │        │ Status   │           │                     │
│       │        └──────────┘           │                     │
│       │               │               │                     │
│       │               ▼               │                     │
│       │        ┌──────────┐           │                     │
│       │        │ Generate │           │                     │
│       │        │ Report   │           │                     │
│       │        └──────────┘           │                     │
│       │               │               │                     │
│       │               ▼               │                     │
│       │        ┌──────────┐           │                     │
│       │        │ Send     │           │                     │
│       │        │ Notif    │           │                     │
│       │        └──────────┘           │                     │
│       │               │               │                     │
│       └───────────────┴───────────────┘                     │
│                     │                                       │
│                     ▼                                       │
│              Return 200 OK                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Security Steps:**
1. Verify request source (IP whitelist)
2. Validate signature using `SHA512(orderId + statusCode + grossAmount + ServerKey)`
3. Idempotent processing (check if already processed)
4. Update in transaction
5. Send notification

---

## 5. SUMMARY

This architecture provides:

✅ **Scalability:** Modular, domain-driven structure
✅ **Maintainability:** Clear separation of concerns
✅ **Security:** RBAC, rate limiting, CSRF, input validation
✅ **Performance:** Redis caching, SSR, optimized queries
✅ **Reliability:** Transactions, soft deletes, audit logs
✅ **Developer Experience:** TypeScript, consistent patterns

---

*Next Step: STEP 2 - Database Design (Prisma Schema)*
