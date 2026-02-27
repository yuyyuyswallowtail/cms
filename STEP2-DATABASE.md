# STEP 2: Database Design (Prisma Schema)

## Enterprise CMS Company Profile - Database Schema

---

## 1. COMPLETE PRISMA SCHEMA

```prisma
// prisma/schema.prisma

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// ============================================
// ENUMS
// ============================================

enum UserStatus {
  ACTIVE
  INACTIVE
  SUSPENDED
  PENDING
}

enum RoleType {
  SUPERADMIN
  ADMIN
  MANAGER
  STAFF
  CUSTOMER
  GUEST
}

enum OrderStatus {
  PENDING
  PROCESSING
  SHIPPED
  DELIVERED
  CANCELLED
  REFUNDED
}

enum PaymentStatus {
  PENDING
  PAID
  FAILED
  EXPIRED
  REFUNDED
  CANCELLED
}

enum PaymentMethod {
  CREDIT_CARD
  BANK_TRANSFER
  E_WALLET
  GOPAY
  OVO
  DANA
  SHOPEEPAY
}

enum ArticleStatus {
  DRAFT
  PUBLISHED
  ARCHIVED
}

enum ProductStatus {
  DRAFT
  ACTIVE
  INACTIVE
  OUT_OF_STOCK
}

enum NotificationType {
  ORDER_CREATED
  ORDER_UPDATED
  PAYMENT_SUCCESS
  PAYMENT_FAILED
  USER_REGISTERED
  LOW_STOCK
  SYSTEM_ALERT
}

enum NotificationTarget {
  USER
  ADMIN
  ALL_ADMINS
  SPECIFIC_ROLE
}

enum NotificationChannel {
  IN_APP
  EMAIL
  BOTH
}

// ============================================
// USER & AUTHENTICATION
// ============================================

model User {
  id            String    @id @default(uuid())
  email         String    @unique
  password      String
  name          String?
  phone         String?
  avatar        String?
  status        UserStatus @default(ACTIVE)
  emailVerified Boolean  @default(false)
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  deletedAt     DateTime?

  // Relations
  roleId        String
  role          Role      @relation(fields: [roleId], references: [id], onDelete: Restrict)
  
  orders        Order[]
  payments      Payment[]
  carts         Cart[]
  notifications Notification[] @relation("UserNotifications")
  activities    ActivityLog[]
  testimonials  Testimonial[]
  
  // OTP
  otpVerifications OTPVerification[]

  @@index([email])
  @@index([roleId])
  @@index([status])
  @@index([deletedAt])
}

model Role {
  id          String   @id @default(uuid())
  name        String   @unique
  type        RoleType @default(CUSTOMER)
  description String?
  isDefault   Boolean  @default(false)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  // Max 2 superadmins constraint handled in application layer
  // Relations
  permissions Permission[]
  users       User[]

  @@index([type])
  @@index([deletedAt])
}

model Permission {
  id          String   @id @default(uuid())
  name        String   @unique
  resource    String   // e.g., "product", "order", "user"
  action      String   // e.g., "create", "read", "update", "delete"
  description String?
  createdAt   DateTime @default(now())

  // Relations
  roles       Role[]

  @@index([resource])
  @@index([resource, action])
}

// ============================================
// COMPANY PROFILE
// ============================================

model CompanyProfile {
  id          String   @id @default(uuid())
  name        String
  slug        String   @unique
  description String?  @db.Text
  vision      String?  @db.Text
  mission     String?  @db.Text
  logo        String?
  favicon     String?
  email       String?
  phone       String?
  address     String?
  city        String?
  country     String?
  latitude    Decimal? @db.Decimal(10, 8)
  longitude   Decimal? @db.Decimal(11, 8)
  socialMedia Json?    // { facebook, twitter, instagram, linkedin, youtube }
  workingHours Json?   // { monday: "09:00-18:00", ... }
  tagline     String?
  heroImage   String?
  status      Boolean  @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  testimonials Testimonial[]
  portfolios   Portfolio[]

  @@index([slug])
  @@index([deletedAt])
}

// ============================================
// PRODUCTS
// ============================================

model ProductCategory {
  id          String    @id @default(uuid())
  name        String
  slug        String    @unique
  description String?   @db.Text
  image       String?
  parentId    String?
  parent      ProductCategory? @relation("CategoryHierarchy", fields: [parentId], references: [id])
  children    ProductCategory[] @relation("CategoryHierarchy")
  products    Product[]
  createdAt   DateTime  @default(now())
  updatedAt   DateTime  @updatedAt
  deletedAt   DateTime?

  @@index([slug])
  @@index([parentId])
  @@index([deletedAt])
}

model Product {
  id          String        @id @default(uuid())
  name        String
  slug        String        @unique
  description String?       @db.Text
  price       Decimal       @db.Decimal(12, 2)
  costPrice   Decimal?      @db.Decimal(12, 2)
  stock       Int           @default(0)
  sku         String?       @unique
  status      ProductStatus @default(DRAFT)
  featured    Boolean       @default(false)
  weight      Decimal?      @db.Decimal(10, 2) // in grams
  dimensions  Json?         // { length, width, height }
  createdAt   DateTime      @default(now())
  updatedAt   DateTime      @updatedAt
  deletedAt   DateTime?

  // Relations
  categoryId  String
  category    ProductCategory @relation(fields: [categoryId], references: [id], onDelete: SetNull)
  images      ProductImage[]
  orderItems  OrderItem[]
  carts       Cart[]
  tags        ProductTag[]

  @@index([slug])
  @@index([categoryId])
  @@index([status])
  @@index([featured])
  @@index([deletedAt])
}

model ProductImage {
  id         String   @id @default(uuid())
  url        String
  altText    String?
  position   Int      @default(0)
  isPrimary  Boolean  @default(false)
  createdAt  DateTime @default(now())

  // Relations
  productId  String
  product    Product  @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@index([productId])
}

model Tag {
  id        String   @id @default(uuid())
  name      String   @unique
  slug      String   @unique
  color     String?  // hex color for UI
  createdAt DateTime @default(now())

  // Relations
  products  ProductTag[]
  articles  ArticleTag[]

  @@index([slug])
}

model ProductTag {
  id        String   @id @default(uuid())
  productId String
  tagId     String

  product   Product  @relation(fields: [productId], references: [id], onDelete: Cascade)
  tag       Tag      @relation(fields: [tagId], references: [id], onDelete: Cascade)

  @@unique([productId, tagId])
  @@index([productId])
  @@index([tagId])
}

// ============================================
// SERVICES
// ============================================

model Service {
  id          String   @id @default(uuid())
  name        String
  slug        String   @unique
  description String?  @db.Text
  shortDesc   String?  @db.Text
  icon        String?  // Icon name or URL
  image       String?
  price       Decimal? @db.Decimal(12, 2)
  featured    Boolean  @default(false)
  status      Boolean  @default(true)
  order       Int      @default(0)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  @@index([slug])
  @@index([featured])
  @@index([deletedAt])
}

// ============================================
// ARTICLES (Markdown CMS)
// ============================================

model Article {
  id          String       @id @default(uuid())
  title       String
  slug        String       @unique
  content     String       @db.Text // Markdown content
  excerpt     String?      @db.Text
  coverImage  String?
  status      ArticleStatus @default(DRAFT)
  viewCount   Int          @default(0)
  featured    Boolean      @default(false)
  publishedAt DateTime?
  authorId    String?
  createdAt   DateTime     @default(now())
  updatedAt   DateTime     @updatedAt
  deletedAt   DateTime?

  // Relations
  tags        ArticleTag[]

  @@index([slug])
  @@index([status])
  @@index([publishedAt])
  @@index([authorId])
  @@index([deletedAt])
}

model ArticleTag {
  id        String   @id @default(uuid())
  articleId String
  tagId     String

  article   Article  @relation(fields: [articleId], references: [id], onDelete: Cascade)
  tag       Tag      @relation(fields: [tagId], references: [id], onDelete: Cascade)

  @@unique([articleId, tagId])
  @@index([articleId])
  @@index([tagId])
}

// ============================================
// ORDERS & PAYMENTS
// ============================================

model Order {
  id            String      @id @default(uuid())
  orderNumber   String      @unique
  status        OrderStatus @default(PENDING)
  subtotal      Decimal     @db.Decimal(12, 2)
  tax           Decimal     @db.Decimal(12, 2) @default(0)
  shippingCost  Decimal     @db.Decimal(12, 2) @default(0)
  discount      Decimal     @db.Decimal(12, 2) @default(0)
  total         Decimal     @db.Decimal(12, 2)
  notes         String?     @db.Text
  shippingName  String?
  shippingPhone String?
  shippingAddress String?
  shippingCity String?
  shippingPostalCode String?
  createdAt     DateTime    @default(now())
  updatedAt     DateTime    @updatedAt
  deletedAt     DateTime?

  // Relations
  userId        String
  user          User        @relation(fields: [userId], references: [id], onDelete: SetNull)
  items         OrderItem[]
  payments      Payment[]

  @@index([orderNumber])
  @@index([userId])
  @@index([status])
  @@index([createdAt])
  @@index([deletedAt])
}

model OrderItem {
  id          String   @id @default(uuid())
  quantity    Int
  price       Decimal  @db.Decimal(12, 2) // Price at time of order
  total       Decimal  @db.Decimal(12, 2)
  createdAt   DateTime @default(now())

  // Relations
  orderId     String
  order       Order    @relation(fields: [orderId], references: [id], onDelete: Cascade)
  productId   String
  product     Product  @relation(fields: [productId], references: [id], onDelete: SetNull)

  @@index([orderId])
  @@index([productId])
}

model Payment {
  id              String        @id @default(uuid())
  midtransOrderId String?       @unique
  midtransToken   String?
  midtransUrl     String?
  amount          Decimal       @db.Decimal(12, 2)
  method          PaymentMethod?
  status          PaymentStatus  @default(PENDING)
  paidAt          DateTime?
  expiryDate      DateTime?
  createdAt       DateTime      @default(now())
  updatedAt       DateTime      @updatedAt

  // Relations
  orderId         String
  order           Order         @relation(fields: [orderId], references: [id], onDelete: Cascade)
  userId          String
  user            User          @relation(fields: [userId], references: [id], onDelete: SetNull)
  reports         FinancialReport[]

  @@index([orderId])
  @@index([userId])
  @@index([status])
  @@index([midtransOrderId])
}

// ============================================
// FINANCIAL REPORTS
// ============================================

model FinancialReport {
  id          String   @id @default(uuid())
  type        String   // DAILY, WEEKLY, MONTHLY, YEARLY
  periodStart DateTime
  periodEnd   DateTime
  revenue     Decimal  @db.Decimal(14, 2)
  orders      Int      @default(0)
  avgOrder    Decimal  @db.Decimal(12, 2)
  createdAt   DateTime @default(now())

  // Relations
  paymentId   String?
  payment     Payment? @relation(fields: [paymentId], references: [id])

  @@index([type])
  @@index([periodStart])
}

// ============================================
// CART
// ============================================

model Cart {
  id          String   @id @default(uuid())
  quantity    Int      @default(1)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  // Relations
  userId      String
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  productId   String
  product     Product  @relation(fields: [productId], references: [id], onDelete: Cascade)

  @@unique([userId, productId])
  @@index([userId])
  @@index([productId])
}

// ============================================
// PORTFOLIO
// ============================================

model Portfolio {
  id          String   @id @default(uuid())
  title       String
  slug        String   @unique
  description String?  @db.Text
  clientName  String?
  image       String?
  images      String[] // Multiple images
  link        String?
  category    String?
  status      Boolean  @default(true)
  order       Int      @default(0)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  // Relations
  companyId   String
  company     CompanyProfile @relation(fields: [companyId], references: [id], onDelete: Cascade)

  @@index([slug])
  @@index([companyId])
  @@index([deletedAt])
}

// ============================================
// TESTIMONIALS
// ============================================

model Testimonial {
  id          String   @id @default(uuid())
  name        String
  position    String?
  company     String?
  content     String   @db.Text
  avatar      String?
  rating      Int      @default(5) // 1-5
  isFeatured  Boolean  @default(false)
  status      Boolean  @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  // Relations
  userId      String?
  user        User?    @relation(fields: [userId], references: [id])
  companyId   String?
  company     CompanyProfile? @relation(fields: [companyId], references: [id])

  @@index([deletedAt])
}

// ============================================
// NOTIFICATIONS
// ============================================

model Notification {
  id          String            @id @default(uuid())
  type        NotificationType
  title       String
  message     String            @db.Text
  data        Json?             // Additional data
  channel     NotificationChannel @default(IN_APP)
  target      NotificationTarget @default(ADMIN)
  targetRole  String?           // For SPECIFIC_ROLE target
  targetUser  String?           // For SPECIFIC_USER target
  isRead      Boolean           @default(false)
  readAt      DateTime?
  createdAt   DateTime          @default(now())

  // Relations
  userId      String?
  user        User?             @relation("UserNotifications", fields: [userId], references: [id])

  @@index([type])
  @@index([target])
  @@index([isRead])
  @@index([createdAt])
}

// ============================================
// ACTIVITY LOG (AUDIT)
// ============================================

model ActivityLog {
  id          String   @id @default(uuid())
  action      String   // CREATE, UPDATE, DELETE, LOGIN, LOGOUT, etc.
  resource    String   // e.g., "user", "product", "order"
  resourceId  String?
  description String?
  ipAddress   String?
  userAgent   String?
  metadata    Json?
  createdAt   DateTime @default(now())

  // Relations
  userId      String?
  user        User?    @relation(fields: [userId], references: [id])

  @@index([action])
  @@index([resource])
  @@index([resourceId])
  @@index([userId])
  @@index([createdAt])
}

// ============================================
// VISITOR LOG (ANALYTICS)
// ============================================

model VisitorLog {
  id          String   @id @default(uuid())
  sessionId   String?
  ipAddress   String?
  userAgent   String?
  referrer    String?
  pageUrl     String
  country     String?
  city        String?
  device      String?  // desktop, mobile, tablet
  browser     String?
  os          String?
  createdAt   DateTime @default(now())

  @@index([pageUrl])
  @@index([createdAt])
}

// ============================================
// OTP VERIFICATION
// ============================================

model OTPVerification {
  id          String   @id @default(uuid())
  email       String
  otp         String
  type        String   // VERIFY_EMAIL, FORGOT_PASSWORD, CHANGE_EMAIL
  expiresAt   DateTime
  isUsed      Boolean  @default(false)
  createdAt   DateTime @default(now())

  // Relations
  userId      String
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([email])
  @@index([otp])
  @@index([expiresAt])
}
```

---

## 2. RELATIONSHIP DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           ENTITY RELATIONSHIPS                                       │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│    ┌─────────┐         ┌──────────────┐         ┌─────────────┐                    │
│    │   Role  │◄───────►│    User      │◄───────►│    Order     │                    │
│    └────┬────┘         └──────┬───────┘         └──────┬──────┘                    │
│         │                    │                        │                           │
│         │                    │                        │                           │
│         │              ┌─────▼─────┐            ┌─────▼──────┐                    │
│         └─────────────►│ Permission│            │  OrderItem │                    │
│                        └───────────┘            └──────┬──────┘                    │
│                                                        │                           │
│                                                        ▼                           │
│    ┌─────────────┐         ┌─────────────┐     ┌─────────────┐                   │
│    │   Company   │◄────────│  Portfolio  │     │   Product   │                   │
│    │   Profile   │         └─────────────┘     └──────┬──────┘                   │
│    └──────┬──────┘                                   │                           │
│           │                                   ┌─────▼─────┐                       │
│    ┌──────▼──────┐                               │  Product  │───────┐            │
│    │ Testimonial │                               │  Category │       │            │
│    └─────────────┘                               └───────────┘       │            │
│                                                                        │            │
│    ┌─────────────┐     ┌─────────────┐                          ┌─────▼─────┐    │
│    │   Service   │     │   Article   │◄─────────────►          │  Product  │    │
│    └─────────────┘     └──────┬──────┘                          │   Image   │    │
│                                │                                 └───────────┘    │
│                         ┌──────▼──────┐                                 │            │
│                         │ArticleTag   │◄──────────────►              │            │
│                         └──────┬──────┘                               │            │
│                                │                                 ┌─────▼─────┐    │
│                         ┌──────▼──────┐                               │   Tag     │    │
│                         │    Tag      │◄───────────────────────────│           │    │
│                         └─────────────┘                               └───────────┘    │
│                                                                                      │
│    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐                │
│    │    Cart     │◄───────►│   Payment    │◄───────►│  Financial  │                │
│    └─────────────┘         └──────┬──────┘         │   Report    │                │
│                                   │                └─────────────┘                │
│                                   ▼                                                   │
│    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐                │
│    │    OTP      │◄───────│  Notification│◄───────│  Activity   │                │
│    └─────────────┘         └──────────────┘         │    Log      │                │
│                                                      └─────────────┘                │
│    ┌─────────────┐                                                               │
│    │ VisitorLog  │  (Standalone - no foreign keys)                               │
│    └─────────────┘                                                               │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. RELATIONSHIP EXPLANATIONS

### 3.1 User & Authentication Flow

```
User ───► Role (Many-to-One)
    │
    ├──► OTPVerification (One-to-Many)
    ├──► Order (One-to-Many)
    ├──► Payment (One-to-Many)
    ├──► Cart (One-to-Many)
    ├──► Testimonial (One-to-Many, optional)
    └──► Notification (One-to-Many, as recipient)

Role ───► Permission (Many-to-Many via implicit relation)
```

- Each user has ONE role (roleId foreign key)
- Each role can have MULTIPLE permissions
- RoleType enum: SUPERADMIN, ADMIN, MANAGER, STAFF, CUSTOMER, GUEST
- Max 2 Superadmins: Enforced in application layer (service/repository)

### 3.2 Product Catalog Flow

```
ProductCategory (Self-referencing)
    │
    ├── parentId ──► ProductCategory (parent)
    └── children ──► ProductCategory[] (subcategories)

Product ───► ProductCategory (Many-to-One)
Product ───► ProductImage (One-to-Many)
Product ───► ProductTag (One-to-Many) ──► Tag (Many-to-One)
Product ───► OrderItem (One-to-Many)
Product ───► Cart (One-to-Many)
```

### 3.3 Order & Payment Flow

```
User ───► Order (One-to-Many)
Order ───► OrderItem (One-to-Many) ──► Product (Many-to-One)
Order ───► Payment (One-to-Many)
Payment ───► FinancialReport (One-to-Many, optional)
```

- Order contains multiple OrderItems
- Each OrderItem references a Product
- Payment can generate FinancialReport (for each successful transaction)

### 3.4 CMS Content Flow

```
CompanyProfile ───► Portfolio (One-to-Many)
CompanyProfile ───► Testimonial (One-to-Many)

Article ───► ArticleTag (One-to-Many) ──► Tag (Many-to-One)
Article ───► User (author, optional)
```

### 3.5 Notification System

```
User ◄─── Notification (One-to-Many, as recipient)
```

- Notifications are user-scoped
- Target types: USER, ADMIN, ALL_ADMINS, SPECIFIC_ROLE
- Channels: IN_APP, EMAIL, BOTH

### 3.6 Audit Trail

```
User ◄─── ActivityLog (One-to-Many)
```

- Every action tracked: CREATE, UPDATE, DELETE, LOGIN, LOGOUT
- Resource + resourceId for traceability
- IP address + user agent captured

---

## 4. INDEX STRATEGY

### Frequently Queried Fields (Indexes Created)

| Table | Index | Purpose |
|-------|-------|---------|
| User | email | Login lookups |
| User | roleId | Role-based queries |
| User | status | User filtering |
| Role | type | Role type queries |
| Product | slug | URL lookups |
| Product | categoryId | Category filtering |
| Product | featured | Featured products |
| ProductCategory | slug | URL lookups |
| ProductCategory | parentId | Hierarchy queries |
| Order | orderNumber | Order lookups |
| Order | userId | User orders |
| Order | status | Status filtering |
| Order | createdAt | Date range queries |
| Payment | orderId | Order payments |
| Payment | midtransOrderId | Midtrans webhooks |
| Article | slug | URL lookups |
| Article | publishedAt | Publishing workflow |
| Article | status | Draft/Published filtering |
| Tag | slug | URL lookups |
| Notification | isRead | Unread notifications |
| Notification | createdAt | Recent notifications |
| ActivityLog | createdAt | Audit queries |
| ActivityLog | userId + createdAt | User activity |
| VisitorLog | createdAt | Analytics |
| VisitorLog | pageUrl | Page analytics |

---

## 5. SOFT DELETE STRATEGY

All main entities include:
- `deletedAt: DateTime?` - Nullable timestamp
- `@@index([deletedAt])` - For filtering

**Query Pattern:**
```typescript
// Always filter out soft-deleted records
const products = await prisma.product.findMany({
  where: {
    deletedAt: null,  // Exclude soft-deleted
    status: 'ACTIVE'
  }
});
```

**Delete Implementation:**
```typescript
// Soft delete
await prisma.product.update({
  where: { id },
  data: { deletedAt: new Date() }
});

// Restore
await prisma.product.update({
  where: { id },
  data: { deletedAt: null }
});
```

---

## 6. MAX 2 SUPERADMIN CONSTRAINT

### Implementation (Application Layer)

Since Prisma doesn't support complex constraints, enforce in service layer:

```typescript
// services/role.service.ts
export class RoleService {
  async createSuperadmin(data: CreateRoleDTO) {
    const superadminCount = await prisma.role.count({
      where: { type: 'SUPERADMIN', deletedAt: null }
    });
    
    if (superadminCount >= 2) {
      throw new Error('Maximum 2 superadmins allowed');
    }
    
    return prisma.role.create({ data });
  }
  
  async assignSuperadmin(userId: string) {
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      include: { role: true }
    });
    
    if (user?.role?.type === 'SUPERADMIN') {
      throw new Error('User is already a superadmin');
    }
    
    const superadminCount = await prisma.role.count({
      where: { type: 'SUPERADMIN', deletedAt: null }
    });
    
    if (superadminCount >= 2) {
      throw new Error('Maximum 2 superadmins allowed');
    }
    
    // Assign superadmin role...
  }
}
```

---

## 7. SUMMARY

| Entity | Primary Key | Relations | Soft Delete | Indexes |
|--------|-------------|-----------|-------------|---------|
| User | uuid | Role, Order, Payment, Cart, Notification, ActivityLog | ✅ | 4 |
| Role | uuid | User, Permission | ✅ | 2 |
| Permission | uuid | Role | ❌ | 2 |
| CompanyProfile | uuid | Portfolio, Testimonial | ✅ | 2 |
| Product | uuid | Category, Images, Tags, OrderItems, Cart | ✅ | 5 |
| ProductCategory | uuid | Parent, Children, Products | ✅ | 4 |
| ProductImage | uuid | Product | ❌ | 1 |
| Tag | uuid | Products, Articles | ❌ | 1 |
| Service | uuid | - | ✅ | 3 |
| Article | uuid | Tags | ✅ | 5 |
| Order | uuid | User, Items, Payments | ✅ | 5 |
| OrderItem | uuid | Order, Product | ❌ | 2 |
| Payment | uuid | Order, User, Reports | ❌ | 4 |
| FinancialReport | uuid | Payment (optional) | ❌ | 2 |
| Cart | uuid | User, Product | ❌ | 3 |
| Portfolio | uuid | Company | ✅ | 3 |
| Testimonial | uuid | User, Company | ✅ | 2 |
| Notification | uuid | User | ❌ | 4 |
| ActivityLog | uuid | User | ❌ | 5 |
| VisitorLog | uuid | - | ❌ | 2 |
| OTPVerification | uuid | User | ❌ | 3 |

---

*Next Step: STEP 3 - Authentication & RBAC Implementation*
