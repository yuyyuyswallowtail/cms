# Enterprise CMS System Architecture

## Overview
An enterprise-grade CMS for company profiles with RBAC, payment processing, content management, and analytics.

---

## 1. High-Level System Architecture

### 1.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CLIENT LAYER                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Web App   │  │  Mobile PWA │  │   Admin     │  │  Dashboard  │        │
│  │  (Next.js)  │  │   (Next.js) │  │   Panel     │  │    Panel    │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼───────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           API GATEWAY LAYER                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Next.js API Routes (App Router)                  │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │    │
│  │  │  /api/auth │  │ /api/cms   │  │ /api/pay   │  │ /api/admin  │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              Middleware Layer (Rate Limit, CSRF, Auth)              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SERVICE LAYER                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ AuthService│  │ CMSService │  │PaymentService│ │AnalyticsService│      │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ NotifService│  │ExportService│  │CacheService │  │ MailService │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        REPOSITORY LAYER                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ UserRepo    │  │ ProductRepo │  │ ArticleRepo │  │ OrderRepo   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA LAYER                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐            │
│  │   PostgreSQL     │  │      Redis       │  │    Midtrans     │            │
│  │  (Primary DB)    │  │   (Cache/Session)│  │ (Payment Gateway)│           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘            │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                                 │
│  │    Nodemailer    │  │   Cloud Storage  │                                 │
│  │  (Email Service) │  │  (Images/Files)  │                                 │
│  └──────────────────┘  └──────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Layer Explanations

#### Frontend Layer (Next.js App Router)
- **Technology**: Next.js 14+ with App Router, TypeScript
- **UI Components**: shadcn/ui, Framer Motion
- **Forms**: React Hook Form + Zod validation
- **State Management**: Server Actions, React Query (optional)
- **Themes**: Dark/Light/System mode support

#### Backend Layer (Next.js API Routes)
- **Framework**: Next.js App Router (Route Handlers)
- **Business Logic**: Modular services in `/services`
- **Data Access**: Repository pattern in `/repositories`
- **Validation**: Zod schemas in `/validations`
- **Type Safety**: Strict TypeScript throughout

#### Database Layer (PostgreSQL + Prisma)
- **ORM**: Prisma with PostgreSQL
- **Soft Delete**: All tables include `deletedAt`
- **Audit**: ActivityLog for tracking changes
- **Relations**: Proper foreign keys and many-to-many

#### Cache Layer (Redis)
- **Sessions**: HTTP-only cookie + Redis session store
- **API Cache**: Product catalog, dashboard summaries
- **Rate Limiting**: Token bucket algorithm
- **OTP Storage**: Time-limited OTP codes

#### Payment Gateway Integration (Midtrans)
- **API**: Snap API for checkout, Core API for management
- **Webhooks**: Secure signature verification
- **Transaction Safety**: Idempotency keys, status reconciliation

#### Email Service (Nodemailer)
- **OTP Verification**: Email verification, password reset
- **Notifications**: Order confirmations, admin alerts
- **Templates**: HTML email templates

#### Security Layer
- **Authentication**: Session-based with salted tokens
- **Authorization**: RBAC with middleware guards
- **CSRF**: Double-submit cookie pattern
- **Rate Limiting**: Per-IP, per-user limits
- **Input Validation**: Zod schemas for all inputs

#### Notification Feature
- **In-App**: Database-backed notification system
- **Real-time**: Polling/SSE for updates (optional)
- **Triggers**: Order, payment, user, stock alerts

---

## 2. Scalable Folder Structure

```
/cms
├── .github/
│   └── workflows/
│       └── ci.yml
├── .vscode/
│   ├── extensions.json
│   └── settings.json
├── prisma/
│   ├── migrations/
│   ├── schema.prisma
│   └── seed.ts
├── public/
│   ├── images/
│   └── files/
├── src/
│   ├── app/
│   │   ├── (auth)/
│   │   │   ├── login/
│   │   │   ├── register/
│   │   │   ├── verify/
│   │   │   └── forgot-password/
│   │   ├── (cms)/
│   │   │   ├── articles/
│   │   │   ├── products/
│   │   │   ├── services/
│   │   │   ├── portfolio/
│   │   │   └── testimonials/
│   │   ├── (dashboard)/
│   │   │   ├── overview/
│   │   │   ├── orders/
│   │   │   ├── customers/
│   │   │   ├── reports/
│   │   │   ├── settings/
│   │   │   └── notifications/
│   │   ├── api/
│   │   │   ├── auth/
│   │   │   ├── cms/
│   │   │   ├── payment/
│   │   │   ├── export/
│   │   │   └── webhooks/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   └── globals.css
│   ├── components/
│   │   ├── ui/                    # shadcn/ui components
│   │   ├── shared/               # Shared components
│   │   │   ├── DataTable/
│   │   │   ├── FileUpload/
│   │   │   ├── MarkdownEditor/
│   │   │   └── Toast/
│   │   ├── layout/
│   │   │   ├── Sidebar/
│   │   │   ├── Header/
│   │   │   └── Footer/
│   │   └── charts/               # Dashboard charts
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── useCart.ts
│   │   ├── useNotification.ts
│   │   └── useDebounce.ts
│   ├── lib/
│   │   ├── db.ts                 # Prisma client
│   │   ├── redis.ts              # Redis client
│   │   ├── mail.ts               # Nodemailer
│   │   ├── midtrans.ts           # Midtrans client
│   │   ├── utils.ts              # Utility functions
│   │   └── constants.ts
│   ├── middleware/
│   │   ├── auth.ts               # Session validation
│   │   ├── rbac.ts               # Role-based access
│   │   ├── csrf.ts               # CSRF protection
│   │   └── rateLimit.ts          # Rate limiting
│   ├── modules/                  # Feature modules
│   │   ├── auth/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   └── types.ts
│   │   ├── cms/
│   │   ├── order/
│   │   ├── payment/
│   │   └── notification/
│   ├── repositories/             # Data access layer
│   │   ├── UserRepository.ts
│   │   ├── ProductRepository.ts
│   │   ├── OrderRepository.ts
│   │   └── ...
│   ├── services/                # Business logic
│   │   ├── AuthService.ts
│   │   ├── CMSService.ts
│   │   ├── PaymentService.ts
│   │   ├── NotificationService.ts
│   │   ├── CacheService.ts
│   │   ├── ExportService.ts
│   │   └── AnalyticsService.ts
│   ├── types/                   # Global types
│   │   ├── index.ts
│   │   └── enums.ts
│   └── validations/             # Zod schemas
│       ├── auth.ts
│       ├── cms.ts
│       ├── order.ts
│       └── payment.ts
├── .env.example
├── .env.local
├── .eslintrc.json
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── next.config.js
├── package.json
├── postcss.config.js
├── README.md
├── tailwind.config.ts
└── tsconfig.json
```

---

## 3. Modular Architecture Separation

### 3.1 `/modules/`
Feature-based organization. Each module contains:
- **components/**: Module-specific UI components
- **hooks/**: Module-specific React hooks
- **types/**: Module-specific TypeScript types

### 3.2 `/services/`
Business logic layer - pure functions, no side effects except:
- Database calls via repositories
- External service calls (Redis, Midtrans, Email)
- Return typed results

### 3.3 `/repositories/`
Data access layer:
- Prisma queries only
- Transaction management
- Soft delete handling
- Pagination logic

### 3.4 `/lib/`
Shared utilities and clients:
- `db.ts`: Prisma singleton
- `redis.ts`: Redis connection
- `mail.ts`: Email transporter
- `midtrans.ts`: Payment client

### 3.5 `/hooks/`
Reusable React hooks:
- Authentication state
- Cart management
- Notifications
- Debounce/throttle

### 3.6 `/middleware/`
Next.js middleware:
- Session validation
- RBAC enforcement
- CSRF protection
- Rate limiting

### 3.7 `/validations/`
Zod schemas for request validation:
- Type-safe input validation
- Reusable across client/server

### 3.8 `/types/`
Global TypeScript types and enums

---

## 4. Key Architecture Explanations

### 4.1 RBAC Enforcement

```
User → Role → Permission
  ↓
Has multiple roles (optional)
  ↓
Role has many permissions
  ↓
Permission = action + resource
  ↓
Middleware checks: user.can('read', 'products')
```

**Implementation**:
1. Database: Role, Permission, UserRole tables
2. Session: Store userId + roleIds
3. Middleware: Check permission before route access
4. Component: Conditional rendering based on permission

### 4.2 Caching Strategy

| Data Type | Cache Strategy | TTL | Invalidation |
|-----------|---------------|-----|--------------|
| Session | Redis | 24h (sliding) | Logout/expiry |
| Product Catalog | Redis | 5min | Product CRUD |
| Dashboard Summary | Redis | 1min | New order/payment |
| Cart | Redis | 24h | Cart modify |
| OTP | Redis | 5min (absolute) | Verify/expire |
| Search Results | Redis | 10min | Product change |

**Cache-Aside Pattern**:
1. Check cache → hit → return
2. Cache miss → fetch DB → store cache → return
3. Write → invalidate cache → update DB

### 4.3 Transaction Handling

**Prisma Transactions**:
```typescript
// Within service
const result = await prisma.$transaction(async (tx) => {
  const order = await tx.order.create({...});
  await tx.orderItem.createMany({...});
  await tx.payment.create({...});
  return order;
});
```

**Use Cases**:
- Order creation (order + items + payment)
- User registration (user + role + profile)
- Product batch operations

### 4.4 Webhook Payment Flow

```
1. User completes payment on Midtrans
2. Midtrans POST to /api/webhooks/midtrans
3. Verify signature (X-Midtrans-Signature)
4. Find order by transactionId
5. Update order status (prisma.$transaction)
6. Create notification
7. Invalidate cache
8. Return 200 OK
9. Client polls /api/orders/{id} → gets updated status
```

**Idempotency**:
- Store `midtransTransactionId` in Payment table
- Skip if already processed

---

## 5. Security Considerations

### 5.1 Authentication Flow
- Passwords: bcrypt with salt
- Sessions: UUID + timestamp + salted hash
- Tokens: HTTP-only, Secure, SameSite=Strict cookies
- Redis: Session data with TTL

### 5.2 CSRF Protection
- Double-submit cookie pattern
- Generate on login
- Validate on state-changing requests

### 5.3 Rate Limiting
- **API**: 100 req/min for authenticated, 20 req/min for anonymous
- **Auth**: 5 req/min for login, 3 req/15min for OTP
- **Payment**: 10 req/min

### 5.4 Input Validation
- All inputs: Zod schemas
- File uploads: Max 10MB, image types only
- SQL: Parameterized queries (Prisma handles this)
- XSS: React auto-escapes, DOMPurify for markdown

---

## 6. Scalability Considerations

### 6.1 Database
- Read replicas for read-heavy operations
- Connection pooling (Prisma Accelerate or PgBouncer)
- Indexing on frequently queried fields

### 6.2 Caching
- Redis Cluster for high availability
- Cache warming for critical data
- CDN for static assets

### 6.3 Application
- Stateless API (session in Redis)
- Horizontal scaling (multiple instances)
- Background jobs for heavy operations

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
