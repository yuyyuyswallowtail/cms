# Enterprise CMS - Company Profile Management System

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript" alt="TypeScript" />
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis" alt="Redis" />
  <img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma" alt="Prisma" />
</p>

## 📋 Project Overview

Enterprise CMS is a comprehensive content management system designed for company profiles. It provides robust features including role-based access control (RBAC), payment processing, markdown article management, product catalog management, and real-time analytics dashboard.

### Key Features

- 🔐 **Authentication & Security**: Session-based auth with OTP verification, CSRF protection, rate limiting
- 👥 **Role-Based Access Control (RBAC)**: Flexible permission system with 6 user roles
- 📦 **Product Management**: CRUD operations, categories, inventory tracking, CSV export
- 📝 **Markdown Articles**: Full markdown support with image uploads, tags, and sanitized rendering
- 💳 **Payment Integration**: Midtrans payment gateway integration with webhook support
- 📊 **Analytics Dashboard**: Real-time sales charts, revenue tracking, visitor statistics
- 🔔 **Notification System**: Database-backed notifications with role-based targeting
- 🎨 **Modern UI**: shadcn/ui components with Framer Motion animations
- 📱 **Responsive Design**: Dark/Light theme support

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                   │
│   Next.js App Router + shadcn/ui + Framer Motion                       │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          API GATEWAY                                    │
│   Next.js Route Handlers + Middleware (Auth, RBAC, Rate Limit)         │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        SERVICE LAYER                                     │
│   AuthService | CMSService | PaymentService | NotificationService       │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      REPOSITORY LAYER                                   │
│   UserRepository | ProductRepository | OrderRepository                 │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER                                      │
│   PostgreSQL (Prisma) | Redis (Cache/Session) | Midtrans (Payments)    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript |
| Database | PostgreSQL |
| ORM | Prisma |
| Cache/Session | Redis |
| UI Components | shadcn/ui |
| Animations | Framer Motion |
| Forms | React Hook Form + Zod |
| Payment | Midtrans |
| Email | Nodemailer |
| Authentication | Session-based (HTTP-only cookies) |

---

## 📁 Folder Structure

```
src/
├── app/                    # Next.js App Router
│   ├── (auth)/            # Auth pages (login, register)
│   ├── (cms)/             # Public CMS pages
│   ├── (dashboard)/       # Admin dashboard
│   └── api/               # API routes
├── components/
│   ├── ui/                # shadcn/ui components
│   ├── shared/            # Reusable components
│   ├── layout/            # Layout components
│   └── dashboard/         # Dashboard components
├── hooks/                 # Custom React hooks
├── lib/                   # Core utilities
│   ├── db.ts             # Prisma client
│   ├── redis.ts           # Redis client
│   ├── midtrans.ts        # Midtrans client
│   └── utils.ts           # Helper functions
├── middleware/            # Next.js middleware
├── modules/               # Feature modules
├── repositories/         # Data access layer
├── services/             # Business logic
├── types/                # TypeScript types
└── validations/          # Zod schemas
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- PostgreSQL 14+
- Redis 6+
- npm or yarn

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yuyyuyswallowtail/cms.git
cd cms
```

2. **Install dependencies**
```bash
npm install
```

3. **Environment setup**
```bash
cp .env.example .env.local
```

4. **Configure environment variables**
```env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/cms"

# Redis
REDIS_URL="redis://localhost:6379"

# Auth
SESSION_SECRET="your-super-secret-session-key-min-32-chars"
OTP_SECRET="your-otp-secret-min-16-chars"

# Email (SMTP)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USER="your-email@gmail.com"
SMTP_PASS="your-app-password"
SMTP_FROM_NAME="CMS Admin"
SMTP_FROM_EMAIL="admin@yourdomain.com"

# Midtrans
MIDTRANS_SERVER_KEY="your-server-key"
MIDTRANS_CLIENT_KEY="your-client-key"
MIDTRANS_ENV="sandbox"

# App
NODE_ENV="development"
APP_URL="http://localhost:3000"
```

5. **Database setup**
```bash
# Generate Prisma client
npx prisma generate

# Run migrations
npx prisma migrate dev --name init

# (Optional) Seed database
npx prisma db seed
```

6. **Start development server**
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 📖 Database Migration Guide

### Creating a New Migration

```bash
npx prisma migrate dev --name migration_name
```

### Reset Database (Development Only)

```bash
npx prisma migrate reset
```

### View Migration Status

```bash
npx prisma migrate status
```

### Apply Migrations in Production

```bash
npx prisma migrate deploy
```

---

## 🔧 Redis Setup

### Local Development

1. **Using Docker**
```bash
docker run -d -p 6379:6379 redis:7-alpine
```

2. **Using Homebrew (macOS)**
```bash
brew install redis
brew services start redis
```

### Verify Redis Connection

```bash
redis-cli ping
# Should return: PONG
```

---

## 💳 Midtrans Setup

### Sandbox Environment

1. Create account at [Midtrans Dashboard](https://dashboard.sandbox.midtrans.com)
2. Get your Server Key and Client Key
3. Set `MIDTRANS_ENV="sandbox"` in environment

### Production Environment

1. Request production access in Midtrans Dashboard
2. Get production Server Key and Client Key
3. Set `MIDTRANS_ENV="production"` in environment

### Testing Payments

Use Midtrans Sandbox test credentials:
- Credit Card: `4811 1111 1111 1114`
- CVV: `123`
- Exp: `12/25`

---

## 🐳 Docker Deployment

### Development

```bash
docker-compose up -d
```

### Production

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
```

---

## 🔒 Security Best Practices

### Implemented Security Features

- ✅ Session-based authentication with HTTP-only cookies
- ✅ OTP email verification
- ✅ CSRF protection (double-submit cookie pattern)
- ✅ Rate limiting (per-IP and per-user)
- ✅ Input validation with Zod
- ✅ Image upload validation (type & size)
- ✅ SQL injection prevention (via Prisma)
- ✅ XSS prevention (React auto-escaping)
- ✅ Soft delete for data retention

### Recommendations for Production

1. **SSL/TLS**: Enable HTTPS
2. **Environment**: Use environment-specific secrets
3. **Backup**: Regular database backups
4. **Monitoring**: Set up error tracking (Sentry)
5. **Logging**: Use structured logging
6. **Firewall**: Restrict databaseRedis access

---

## 📱/ API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/logout` | User logout |
| POST | `/api/auth/verify-email` | Verify email with OTP |
| POST | `/api/auth/forgot-password` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password |

### Products
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/products` | List products |
| POST | `/api/products` | Create product |
| GET | `/api/products/[id]` | Get product |
| PUT | `/api/products/[id]` | Update product |
| DELETE | `/api/products/[id]` | Delete product |

### Orders
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create order |
| GET | `/api/orders/[id]` | Get order |

### Payments
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/payments/create` | Create payment |
| POST | `/api/webhooks/midtrans` | Midtrans webhook |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/summary` | Dashboard summary |
| GET | `/api/dashboard/sales` | Sales chart data |

---

## 🧪 Testing

```bash
# Run tests
npm run test

# Run tests with coverage
npm run test:coverage

# Run linting
npm run lint

# Run type checking
npm run typecheck
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 🔮 Future Improvements

- [ ] Multi-tenant support
- [ ] Real-time notifications (WebSocket)
- [ ] Mobile app (React Native/Expo)
- [ ] Advanced search (Elasticsearch)
- [ ] Email templates
- [ ] Two-factor authentication (2FA)
- [ ] Audit logs for admin
- [ ] API versioning
- [ ] GraphQL API

---

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Email: support@yourdomain.com

---

<p align="center">Made with ❤️ by Your Team</p>
