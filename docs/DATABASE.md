# STEP 2 — Database Design (Prisma Schema)

## Entity Relationship Diagram

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    User     │────<│  UserRole   │>────│    Role     │
└──────┬──────┘     └─────────────┘     └──────┬──────┘
       │                                        │
       │                                        │
       │     ┌─────────────┐     ┌─────────────┐
       └────>│  UserProfile │     │  Permission │
             └─────────────┘     └──────┬──────┘
                                         │
                                         ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Order    │>────│  OrderItem  │<────│  Product    │
└──────┬──────┘     └─────────────┘     └──────┬──────┘
       │                                        │
       │                                        │
       ▼                                        ▼
┌─────────────┐                          ┌─────────────┐
│  Payment    │                          │ProductCategory
└─────────────┘                          └─────────────┘
                                                 │
                                                 ▼
                                          ┌─────────────┐
                                          │ProductImage │
                                          └─────────────┘

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Article   │>────│ ArticleTag  │<────│    Tag      │
└─────────────┘     └─────────────┘     └─────────────┘

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Service    │     │ Portfolio   │     │ Testimonial │
└─────────────┘     └─────────────┘     └─────────────┘

┌─────────────┐     ┌─────────────┐
│ Notification│     │ ActivityLog│
└──────┬──────┘     └─────────────┘
       │
       ▼
┌─────────────┐
│ VisitorLog  │
└─────────────┘

┌─────────────┐     ┌─────────────┐
│     Cart    │     │OTPVerification│
└─────────────┘     └─────────────┘
```

---

## Prisma Schema

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
  PENDING
  ACTIVE
  SUSPENDED
  BANNED
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
  CONFIRMED
  PROCESSING
  SHIPPED
  DELIVERED
  CANCELLED
  REFUNDED
}

enum PaymentStatus {
  PENDING
  PROCESSING
  COMPLETED
  FAILED
  EXPIRED
  REFUNDED
}

enum PaymentMethod {
  CREDIT_CARD
  BANK_TRANSFER
  E_WALLET
  COD
}

enum ProductStatus {
  DRAFT
  PUBLISHED
  ARCHIVED
}

enum ArticleStatus {
  DRAFT
  PUBLISHED
  ARCHIVED
}

enum NotificationType {
  ORDER_CREATED
  ORDER_STATUS_CHANGED
  PAYMENT_SUCCESS
  PAYMENT_FAILED
  NEW_USER
  LOW_STOCK
  SYSTEM_ALERT
}

enum NotificationTarget {
  USER
  ROLE
  ALL_USERS
}

// ============================================
// USER & AUTHENTICATION
// ============================================

model User {
  id                String    @id @default(uuid())
  email             String    @unique
  password          String
  name              String?
  phone             String?
  avatar            String?
  status            UserStatus @default(PENDING)
  emailVerified     Boolean   @default(false)
  verifiedAt        DateTime?
  lastLoginAt       DateTime?
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt
  deletedAt         DateTime?

  // Relations
  profile           UserProfile?
  roles             UserRole[]
  orders            Order[]
  notifications     Notification[]
  activityLogs      ActivityLog[]
  testimonials      Testimonial[]
  cart              Cart?
  otpVerifications  OTPVerification[]

  @@index([email])
  @@index([status])
  @@index([deletedAt])
}

model UserProfile {
  id          String   @id @default(uuid())
  userId      String   @unique
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  address     String?
  city        String?
  province    String?
  postalCode  String?
  country     String?
  bio         String?  @db.Text
  socialMedia Json?
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}

model Role {
  id          String   @id @default(uuid())
  name        RoleType @unique
  description String?
  isDefault   Boolean  @default(false)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  // Relations
  users       UserRole[]
  permissions Permission[]
}

model UserRole {
  id        String   @id @default(uuid())
  userId    String
  roleId    String
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  role      Role     @relation(fields: [roleId], references: [id], onDelete: Cascade)
  createdAt DateTime @default(now())

  @@unique([userId, roleId])
  @@index([userId])
  @@index([roleId])
}

model Permission {
  id          String   @id @default(uuid())
  name        String   // e.g., "products.read", "orders.write"
  resource    String   // e.g., "products", "orders"
  action      String   // e.g., "read", "write", "delete"
  description String?
  roleId      String
  role        Role     @relation(fields: [roleId], references: [id], onDelete: Cascade)
  createdAt   DateTime @default(now())

  @@unique([roleId, name])
  @@index([resource, action])
}

// ============================================
// COMPANY PROFILE
// ============================================

model CompanyProfile {
  id          String   @id @default(uuid())
  name        String
  slug        String   @unique
  logo        String?
  favicon     String?
  description String?  @db.Text
  vision      String?  @db.Text
  mission     String?  @db.Text
  email       String?
  phone       String?
  address     String?
  city        String?
  province    String?
  postalCode  String?
  country     String?
  latitude    Float?
  longitude   Float?
  socialMedia Json?
  seoMeta     Json?
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  @@index([slug])
}

// ============================================
// PRODUCTS
// ============================================

model Product {
  id              String        @id @default(uuid())
  name            String
  slug            String        @unique
  description     String?       @db.Text
  price           Decimal       @db.Decimal(12, 2)
  costPrice       Decimal?      @db.Decimal(12, 2)
  stock           Int           @default(0)
  lowStockThreshold Int         @default(10)
  sku             String?       @unique
  weight          Float?        // in grams
  dimensions      Json?         // { length, width, height }
  status          ProductStatus @default(DRAFT)
  featured        Boolean       @default(false)
  createdAt       DateTime      @default(now())
  updatedAt       DateTime      @updatedAt
  deletedAt       DateTime?

  // Relations
  categoryId      String?
  category        ProductCategory? @relation(fields: [categoryId], references: [id])
  images          ProductImage[]
  orderItems      OrderItem[]
  cartItems       CartItem[]
  testimonials    Testimonial[]

  @@index([slug])
  @@index([categoryId])
  @@index([status])
  @@index([featured])
  @@index([deletedAt])
}

model ProductCategory {
  id          String   @id @default(uuid())
  name        String
  slug        String   @unique
  description String?  @db.Text
  icon        String?
  parentId    String?
  sortOrder   Int      @default(0)
  isActive    Boolean  @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  // Self-relation for nested categories
  parent      ProductCategory?  @relation("CategoryHierarchy", fields: [parentId], references: [id])
  children    ProductCategory[] @relation("CategoryHierarchy")
  products    Product[]

  @@index([slug])
  @@index([parentId])
}

model ProductImage {
  id         String   @id @default(uuid())
  productId  String
  product    Product  @relation(fields: [productId], references: [id], onDelete: Cascade)
  url        String
  altText    String?
  isPrimary  Boolean  @default(false)
  sortOrder  Int      @default(0)
  createdAt  DateTime @default(now())

  @@index([productId])
}

// ============================================
// SERVICES
// ============================================

model Service {
  id          String   @id @default(uuid())
  name        String
  slug        String   @unique
  description String?  @db.Text
  icon        String?
  price       Decimal? @db.Decimal(12, 2)
  duration    Int?     // in minutes
  features    Json?    // array of features
  isActive    Boolean  @default(true)
  sortOrder   Int      @default(0)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  @@index([slug])
  @@index([deletedAt])
}

// ============================================
// ARTICLES (MARKDOWN)
// ============================================

model Article {
  id          String       @id @default(uuid())
  title       String
  slug        String       @unique
  content     String       @db.Text  // Markdown content
  excerpt     String?      @db.Text
  coverImage  String?
  author      String?
  status      ArticleStatus @default(DRAFT)
  publishedAt DateTime?
  viewCount   Int          @default(0)
  createdAt   DateTime     @default(now())
  updatedAt   DateTime     @updatedAt
  deletedAt   DateTime?

  // Relations
  tags        ArticleTag[]

  @@index([slug])
  @@index([status])
  @@index([publishedAt])
  @@index([deletedAt])
}

model Tag {
  id        String      @id @default(uuid())
  name      String      @unique
  slug      String      @unique
  color     String?     // hex color for UI
  createdAt DateTime    @default(now())

  // Relations
  articles ArticleTag[]

  @@index([slug])
}

model ArticleTag {
  id        String  @id @default(uuid())
  articleId String
  tagId     String
  article   Article @relation(fields: [articleId], references: [id], onDelete: Cascade)
  tag       Tag     @relation(fields: [tagId], references: [id], onDelete: Cascade)

  @@unique([articleId, tagId])
  @@index([articleId])
  @@index([tagId])
}

// ============================================
// PORTFOLIO
// ============================================

model Portfolio {
  id          String   @id @default(uuid())
  title       String
  slug        String   @unique
  description String?  @db.Text
  client      String?
  images      Json?    // array of image URLs
  videoUrl    String?
  link        String?
  sortOrder   Int      @default(0)
  isActive    Boolean  @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  deletedAt   DateTime?

  @@index([slug])
  @@index([deletedAt])
}

// ============================================
// TESTIMONIALS
// ============================================

model Testimonial {
  id         String   @id @default(uuid())
  name       String
  position   String?
  company    String?
  avatar     String?
  content    String   @db.Text
  rating     Int      @default(5) // 1-5
  isActive   Boolean  @default(true)
  userId     String?  // Optional link to User
  productId  String?  // Optional link to Product
  createdAt  DateTime @default(now())
  updatedAt  DateTime @updatedAt

  // Relations
  user       User?    @relation(fields: [userId], references: [id])
  product    Product? @relation(fields: [productId], references: [id])

  @@index([isActive])
}

// ============================================
// ORDERS & PAYMENTS
// ============================================

model Order {
  id                String      @id @default(uuid())
  orderNumber       String      @unique // e.g., "ORD-20260227-XXXX"
  userId            String
  user              User        @relation(fields: [userId], references: [id])
  status            OrderStatus @default(PENDING)
  subtotal          Decimal     @db.Decimal(12, 2)
  taxAmount         Decimal     @db.Decimal(12, 2) @default(0)
  shippingCost      Decimal     @db.Decimal(12, 2) @default(0)
  discountAmount    Decimal     @db.Decimal(12, 2) @default(0)
  totalAmount       Decimal     @db.Decimal(12, 2)
  currency          String      @default("IDR")
  customerName      String
  customerEmail     String
  customerPhone     String?
  shippingAddress   String?     @db.Text
  shippingCity      String?
  shippingProvince  String?
  shippingPostalCode String?
  notes             String?     @db.Text
  createdAt         DateTime    @default(now())
  updatedAt         DateTime    @updatedAt
  deletedAt         DateTime?

  // Relations
  items             OrderItem[]
  payment           Payment?

  @@index([orderNumber])
  @@index([userId])
  @@index([status])
  @@index([createdAt])
  @@index([deletedAt])
}

model OrderItem {
  id          String  @id @default(uuid())
  orderId     String
  order       Order   @relation(fields: [orderId], references: [id], onDelete: Cascade)
  productId   String
  product     Product @relation(fields: [productId], references: [id])
  productName String  // Snapshot of product name
  productSku  String? // Snapshot of SKU
  quantity    Int
  unitPrice   Decimal @db.Decimal(12, 2)
  totalPrice  Decimal @db.Decimal(12, 2)
  createdAt   DateTime @default(now())

  @@index([orderId])
  @@index([productId])
}

model Payment {
  id                   String        @id @default(uuid())
  orderId              String        @unique
  order                Order         @relation(fields: [orderId], references: [id], onDelete: Cascade)
  midtransTransactionId String?     @unique
  midtransOrderId      String?
  method               PaymentMethod
  status               PaymentStatus @default(PENDING)
  amount               Decimal       @db.Decimal(12, 2)
  currency             String        @default("IDR")
  paymentToken         String?       // Midtrans token
  paymentUrl           String?       // Snap redirect URL
  paidAt               DateTime?
  expireAt             DateTime?
  paymentEvidence      String?       // Uploaded proof for COD/manual transfer
  rawResponse          Json?         // Midtrans callback response
  createdAt            DateTime       @default(now())
  updatedAt            DateTime       @updatedAt

  @@index([orderId])
  @@index([midtransTransactionId])
  @@index([status])
  @@index([expireAt])
}

model FinancialReport {
  id          String   @id @default(uuid())
  period      String   // e.g., "2026-02" for monthly
  reportType  String   // "DAILY", "MONTHLY", "YEARLY"
  revenue     Decimal  @db.Decimal(15, 2)
  orders      Int      @default(0)
  averageOrderValue Decimal @db.Decimal(12, 2)
  refunds     Decimal  @db.Decimal(12, 2) @default(0)
  taxes       Decimal  @db.Decimal(12, 2) @default(0)
  expenses    Decimal  @db.Decimal(12, 2) @default(0)
  netProfit   Decimal  @db.Decimal(15, 2)
  details     Json?    // Detailed breakdown
  generatedAt DateTime @default(now())

  @@unique([period, reportType])
  @@index([period])
}

// ============================================
// CART
// ============================================

model Cart {
  id        String    @id @default(uuid())
  userId    String    @unique
  user      User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  items     CartItem[]

  @@index([userId])
}

model CartItem {
  id        String   @id @default(uuid())
  cartId    String
  cart      Cart     @relation(fields: [cartId], references: [id], onDelete: Cascade)
  productId String
  product   Product  @relation(fields: [productId], references: [id])
  quantity  Int      @default(1)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@unique([cartId, productId])
  @@index([cartId])
  @@index([productId])
}

// ============================================
// NOTIFICATIONS
// ============================================

model Notification {
  id          String           @id @default(uuid())
  userId      String?
  user        User?            @relation(fields: [userId], references: [id], onDelete: Cascade)
  targetType  NotificationTarget
  roleId      String?          // For role-based notifications
  type        NotificationType
  title       String
  message     String           @db.Text
  data        Json?            // Additional data
  isRead      Boolean          @default(false)
  readAt      DateTime?
  createdAt   DateTime         @default(now())

  @@index([userId])
  @@index([targetType, roleId])
  @@index([isRead])
  @@index([createdAt])
}

// ============================================
// ACTIVITY LOG (AUDIT)
// ============================================

model ActivityLog {
  id          String   @id @default(uuid())
  userId      String?
  user        User?    @relation(fields: [userId], references: [id])
  action      String   // e.g., "create", "update", "delete"
  resource    String   // e.g., "product", "order"
  resourceId  String?
  description String?
  ipAddress   String?
  userAgent   String?
  metadata    Json?    // Additional context
  createdAt   DateTime @default(now())

  @@index([userId])
  @@index([resource, resourceId])
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
  device      String?  // "desktop", "mobile", "tablet"
  browser     String?
  os          String?
  createdAt   DateTime @default(now())

  @@index([createdAt])
  @@index([pageUrl])
}

// ============================================
// OTP VERIFICATION
// ============================================

model OTPVerification {
  id          String   @id @default(uuid())
  userId      String
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  type        String   // "EMAIL_VERIFICATION", "PASSWORD_RESET", "LOGIN"
  code        String   // Hashed OTP
  attempts    Int      @default(0)
  maxAttempts Int      @default(3)
  expiresAt   DateTime
  verifiedAt  DateTime?
  createdAt   DateTime @default(now())

  @@index([userId, type])
  @@index([expiresAt])
}
```

---

## Relational Structure Explanation

### 1. **User-Role-Permission (RBAC)**
- **User** → has many **UserRole** → belongs to **Role**
- **Role** → has many **Permission**
- Permission = combination of `resource` + `action` (e.g., "products.read")
- **Superadmin constraint**: Logic in application layer limits to 2 superadmins

### 2. **Product-Category-Image**
- **Product** belongs to **ProductCategory** (optional, can be uncategorized)
- **Product** has many **ProductImage** (one can be primary)
- Categories can be nested (parent-child self-relation)

### 3. **Order-Payment**
- **Order** has one **Payment** (1:1)
- **Order** has many **OrderItem** → references **Product**
- OrderItem stores snapshot (name, SKU, price at time of order)

### 4. **Article-Tag (Many-to-Many)**
- **Article** ↔ **Tag**: Many-to-many via **ArticleTag** junction table

### 5. **Cart**
- **Cart** → has many **CartItem** → references **Product**
- One cart per user (created on first add)

### 6. **Audit & Analytics**
- **ActivityLog**: Tracks all user actions for audit trail
- **VisitorLog**: Anonymous page view tracking

### 7. **Soft Delete**
- All major entities have `deletedAt` field
- Prisma queries filter by default: `deletedAt: null`

---

## Superadmin Constraint Logic

```typescript
// In service layer - check before creating superadmin
async function assignSuperadminRole(userId: string) {
  const superadminCount = await prisma.userRole.count({
    where: {
      role: { name: 'SUPERADMIN' },
      user: { deletedAt: null }
    }
  });

  if (superadminCount >= 2) {
    throw new Error('Maximum 2 superadmins allowed');
  }
  // ... assign role
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
