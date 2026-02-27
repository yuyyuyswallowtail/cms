# STEP 7 — Dashboard & Analytics

## 1. Dashboard Overview

The dashboard provides role-based views for different user types:
- **Superadmin/Admin**: Full system overview
- **Manager**: Sales and product performance
- **Staff**: Task-specific views
- **Customer**: Personal order history

---

## 2. Dashboard Service (`src/services/DashboardService.ts`)

```typescript
// src/services/DashboardService.ts
import { db } from '@/lib/db';
import { cacheService } from './CacheService';
import { subDays, startOfDay, endOfDay, startOfMonth, endOfMonth, startOfYear, endOfYear } from 'date-fns';

export interface DashboardSummary {
  totalRevenue: number;
  totalOrders: number;
  totalProducts: number;
  totalUsers: number;
  pendingOrders: number;
  lowStockProducts: number;
  revenueChange: number; // percentage
  ordersChange: number;
}

export interface SalesDataPoint {
  date: string;
  revenue: number;
  orders: number;
}

export class DashboardService {
  private cacheTTL = 60; // 1 minute

  async getSummary(role: string): Promise<DashboardSummary> {
    const cacheKey = `dashboard:summary:${role}`;
    
    // Try cache first
    const cached = await cacheService.get<DashboardSummary>(cacheKey);
    if (cached) return cached;

    const now = new Date();
    const startOfThisMonth = startOfMonth(now);
    const startOfLastMonth = subDays(startOfThisMonth, 1);
    const startOfLastMonth2 = startOfMonth(subDays(startOfThisMonth, 1));

    // This month stats
    const [thisMonthRevenue, thisMonthOrders, lastMonthRevenue, lastMonthOrders, stats] = await Promise.all([
      db.payment.aggregate({
        where: {
          status: 'COMPLETED',
          paidAt: { gte: startOfThisMonth },
        },
        _sum: { amount: true },
        _count: true,
      }),
      db.order.count({
        where: { createdAt: { gte: startOfThisMonth } },
      }),
      db.payment.aggregate({
        where: {
          status: 'COMPLETED',
          paidAt: { gte: startOfLastMonth2, lt: startOfThisMonth },
        },
        _sum: { amount: true },
      }),
      db.order.count({
        where: { createdAt: { gte: startOfLastMonth2, lt: startOfThisMonth } },
      }),
      Promise.all([
        db.product.count({ where: { status: 'PUBLISHED', deletedAt: null } }),
        db.user.count({ where: { status: 'ACTIVE', deletedAt: null } }),
        db.order.count({ where: { status: 'PENDING' } }),
        db.product.count({
          where: {
            stock: { lte: db.product.fields.lowStockThreshold },
            status: 'PUBLISHED',
            deletedAt: null,
          },
        }),
      ]),
    ]);

    const totalRevenue = Number(thisMonthRevenue._sum.amount || 0);
    const totalOrders = thisMonthOrders;
    const lastMonthTotal = Number(lastMonthRevenue._sum.amount || 0);
    const lastMonthOrdersTotal = lastMonthOrders;

    const revenueChange = lastMonthTotal > 0 
      ? ((totalRevenue - lastMonthTotal) / lastMonthTotal) * 100 
      : 0;
    const ordersChange = lastMonthOrdersTotal > 0 
      ? ((totalOrders - lastMonthOrdersTotal) / lastMonthOrdersTotal) * 100 
      : 0;

    const summary: DashboardSummary = {
      totalRevenue,
      totalOrders,
      totalProducts: stats[0],
      totalUsers: stats[1],
      pendingOrders: stats[2],
      lowStockProducts: stats[3],
      revenueChange: Math.round(revenueChange * 10) / 10,
      ordersChange: Math.round(ordersChange * 10) / 10,
    };

    // Cache the result
    await cacheService.set(cacheKey, summary, { ttl: this.cacheTTL });

    return summary;
  }

  async getSalesChart(
    period: 'daily' | 'monthly' | 'yearly',
    startDate?: Date,
    endDate?: Date
  ): Promise<SalesDataPoint[]> {
    const now = new Date();
    let start: Date;
    let groupBy: string;

    switch (period) {
      case 'daily':
        start = startOfDay(subDays(now, 30));
        groupBy = 'date';
        break;
      case 'monthly':
        start = startOfMonth(subDays(now, 365));
        groupBy = 'month';
        break;
      case 'yearly':
        start = startOfYear(subDays(now, 3650));
        groupBy = 'year';
        break;
    }

    const orders = await db.order.findMany({
      where: {
        status: { in: ['CONFIRMED', 'PROCESSING', 'SHIPPED', 'DELIVERED'] },
        createdAt: { gte: startDate || start },
      },
      select: {
        createdAt: true,
        totalAmount: true,
      },
    });

    // Group by period
    const grouped = orders.reduce((acc, order) => {
      let key: string;
      const date = new Date(order.createdAt);
      
      switch (period) {
        case 'daily':
          key = date.toISOString().slice(0, 10);
          break;
        case 'monthly':
          key = date.toISOString().slice(0, 7);
          break;
        case 'yearly':
          key = date.getFullYear().toString();
          break;
      }

      if (!acc[key]) {
        acc[key] = { date: key, revenue: 0, orders: 0 };
      }
      acc[key].revenue += Number(order.totalAmount);
      acc[key].orders += 1;

      return acc;
    }, {} as Record<string, SalesDataPoint>);

    return Object.values(grouped).sort((a, b) => a.date.localeCompare(b.date));
  }

  async getTopProducts(limit: number = 10) {
    return db.orderItem.groupBy({
      by: ['productId'],
      _sum: { quantity: true },
      _count: true,
      orderBy: { _sum: { quantity: 'desc' } },
      take: limit,
    });
  }

  async getTopCategories(limit: number = 5) {
    const result = await db.orderItem.groupBy({
      by: ['productId'],
      _sum: { quantity: true },
      where: {
        product: { categoryId: { not: null } },
      },
    });

    // Get category names
    const productIds = result.map((r) => r.productId);
    const products = await db.product.findMany({
      where: { id: { in: productIds } },
      select: { id: true, categoryId: true },
    });

    const categoryMap = new Map(products.map((p) => [p.id, p.categoryId]));
    const categoryIds = [...new Set([...categoryMap.values()].filter(Boolean))] as string[];
    
    const categories = await db.productCategory.findMany({
      where: { id: { in: categoryIds } },
      select: { id: true, name: true },
    });

    const categoryMap2 = new Map(categories.map((c) => [c.id, c.name]));

    const categorySales = result.reduce((acc, item) => {
      const catId = categoryMap.get(item.productId);
      if (catId) {
        const catName = categoryMap2.get(catId) || 'Unknown';
        if (!acc[catName]) {
          acc[catName] = 0;
        }
        acc[catName] += item._sum.quantity || 0;
      }
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(categorySales)
      .map(([name, sales]) => ({ name, sales }))
      .sort((a, b) => b.sales - a.sales)
      .slice(0, limit);
  }

  async getRecentOrders(limit: number = 10) {
    return db.order.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: {
        user: { select: { name: true, email: true } },
        payment: { select: { status: true } },
      },
    });
  }

  async getVisitorStats(days: number = 30) {
    const start = subDays(new Date(), days);

    const visitors = await db.visitorLog.groupBy({
      by: ['device'],
      where: { createdAt: { gte: start } },
      _count: true,
    });

    const pageViews = await db.visitorLog.count({
      where: { createdAt: { gte: start } },
    });

    const dailyVisitors = await db.visitorLog.groupBy({
      by: ['createdAt'],
      where: { createdAt: { gte: start } },
      _count: true,
    });

    return {
      totalVisitors: visitors.reduce((sum, v) => sum + v._count, 0),
      totalPageViews: pageViews,
      byDevice: visitors.map((v) => ({ device: v.device || 'unknown', count: v._count })),
      dailyVisitors: dailyVisitors.slice(-7), // Last 7 days
    };
  }
}

export const dashboardService = new DashboardService();
```

---

## 3. Dashboard API Routes

### 3.1 Summary API (`src/app/api/dashboard/summary/route.ts`)

```typescript
// src/app/api/dashboard/summary/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { dashboardService } from '@/services/DashboardService';

export async function GET(request: NextRequest) {
  try {
    const rolesHeader = request.headers.get('x-user-roles');
    const roles = rolesHeader ? JSON.parse(rolesHeader) : ['GUEST'];
    
    const summary = await dashboardService.getSummary(roles[0]);
    
    return NextResponse.json(summary);
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

### 3.2 Sales Chart API (`src/app/api/dashboard/sales/route.ts`)

```typescript
// src/app/api/dashboard/sales/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { dashboardService } from '@/services/DashboardService';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const period = (searchParams.get('period') || 'daily') as 'daily' | 'monthly' | 'yearly';
    
    const salesData = await dashboardService.getSalesChart(period);
    
    return NextResponse.json(salesData);
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

---

## 4. Dashboard UI Components

### 4.1 Stat Card (`src/components/dashboard/StatCard.tsx`)

```typescript
// src/components/dashboard/StatCard.tsx
'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  change?: number;
  changeLabel?: string;
  className?: string;
}

export function StatCard({ title, value, icon: Icon, change, changeLabel, className }: StatCardProps) {
  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {change !== undefined && (
          <p className={cn(
            "text-xs mt-1",
            change > 0 ? "text-green-600" : change < 0 ? "text-red-600" : "text-muted-foreground"
          )}>
            {change > 0 ? '+' : ''}{change}% {changeLabel || 'vs last period'}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
```

### 4.2 Sales Chart (`src/components/dashboard/SalesChart.tsx`)

```typescript
// src/components/dashboard/SalesChart.tsx
'use client';

import { useEffect, useState } from 'react';
import { use } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface SalesDataPoint {
  date: string;
  revenue: number;
  orders: number;
}

interface SalesChartProps {
  data: SalesDataPoint[];
  period: 'daily' | 'monthly' | 'yearly';
}

export function SalesChart({ data, period }: SalesChartProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Sales Overview</CardTitle>
        </CardHeader>
        <CardContent className="h-[300px] flex items-center justify-center">
          <p className="text-muted-foreground">Loading chart...</p>
        </CardContent>
      </Card>
    );
  }

  const formatValue = (value: number) => {
    return new Intl.NumberFormat('id-ID', {
      style: 'currency',
      currency: 'IDR',
      notation: 'compact',
    }).format(value);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sales Overview ({period})</CardTitle>
      </CardHeader>
      <CardContent className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorRevenue" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#8884d8" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#8884d8" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis 
              dataKey="date" 
              tick={{ fontSize: 12 }}
              tickFormatter={(value) => {
                const date = new Date(value);
                if (period === 'daily') return date.toLocaleDateString('id-ID', { day: 'numeric', month: 'short' });
                if (period === 'monthly') return date.toLocaleDateString('id-ID', { month: 'short' });
                return value;
              }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              tickFormatter={formatValue}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'white', 
                border: '1px solid #e2e8f0', 
                borderRadius: '8px' 
              }}
              formatter={(value: number) => [formatValue(value), 'Revenue']}
              labelFormatter={(label) => new Date(label).toLocaleDateString('id-ID')}
            />
            <Area 
              type="monotone" 
              dataKey="revenue" 
              stroke="#8884d8" 
              fillOpacity={1} 
              fill="url(#colorRevenue)" 
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
```

### 4.3 Dashboard Page (`src/app/(dashboard)/dashboard/page.tsx`)

```typescript
// src/app/(dashboard)/dashboard/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { StatCard } from '@/components/dashboard/StatCard';
import { SalesChart } from '@/components/dashboard/SalesChart';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { DollarSign, ShoppingCart, Package, Users, AlertTriangle, TrendingUp } from 'lucide-react';

interface DashboardSummary {
  totalRevenue: number;
  totalOrders: number;
  totalProducts: number;
  totalUsers: number;
  pendingOrders: number;
  lowStockProducts: number;
  revenueChange: number;
  ordersChange: number;
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [salesData, setSalesData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchDashboard() {
      try {
        const [summaryRes, salesRes] = await Promise.all([
          fetch('/api/dashboard/summary'),
          fetch('/api/dashboard/sales?period=daily'),
        ]);

        const summaryData = await summaryRes.json();
        const sales = await salesRes.json();

        setSummary(summaryData);
        setSalesData(sales);
      } catch (error) {
        console.error('Failed to fetch dashboard:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchDashboard();
  }, []);

  if (loading) {
    return <div className="p-8">Loading dashboard...</div>;
  }

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('id-ID', {
      style: 'currency',
      currency: 'IDR',
      maximumFractionDigits: 0,
    }).format(value);
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Revenue"
          value={formatCurrency(summary?.totalRevenue || 0)}
          icon={DollarSign}
          change={summary?.revenueChange}
          changeLabel="vs last month"
        />
        <StatCard
          title="Total Orders"
          value={summary?.totalOrders || 0}
          icon={ShoppingCart}
          change={summary?.ordersChange}
          changeLabel="vs last month"
        />
        <StatCard
          title="Total Products"
          value={summary?.totalProducts || 0}
          icon={Package}
        />
        <StatCard
          title="Total Users"
          value={summary?.totalUsers || 0}
          icon={Users}
        />
      </div>

      {/* Alerts */}
      {(summary?.pendingOrders || 0) > 0 || (summary?.lowStockProducts || 0) > 0 ? (
        <div className="grid gap-4 md:grid-cols-2">
          {((summary?.pendingOrders || 0) > 0) && (
            <Card className="border-yellow-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Pending Orders
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{summary?.pendingOrders}</div>
              </CardContent>
            </Card>
          )}
          {((summary?.lowStockProducts || 0) > 0) && (
            <Card className="border-red-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-red-500" />
                  Low Stock Products
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{summary?.lowStockProducts}</div>
              </CardContent>
            </Card>
          )}
        </div>
      ) : null}

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-7">
        <div className="col-span-4">
          <SalesChart data={salesData} period="daily" />
        </div>
      </div>
    </div>
  );
}
```

---

## 5. Role-Based Dashboard Filtering

### 5.1 Dashboard Access Control

```typescript
// src/middleware/dashboard.ts
import { NextRequest, NextResponse } from 'next/server';

const ROLE_DASHBOARD_MAP: Record<string, string> = {
  SUPERADMIN: '/dashboard',
  ADMIN: '/dashboard',
  MANAGER: '/dashboard/manager',
  STAFF: '/dashboard/staff',
  CUSTOMER: '/dashboard/my-orders',
};

export function getDashboardPath(role: string): string {
  return ROLE_DASHBOARD_MAP[role] || '/dashboard/my-orders';
}

export async function dashboardMiddleware(request: NextRequest) {
  const rolesHeader = request.headers.get('x-user-roles');
  const roles = rolesHeader ? JSON.parse(rolesHeader) : ['GUEST'];
  
  const userRole = roles[0];
  const dashboardPath = getDashboardPath(userRole);
  
  // Redirect to appropriate dashboard
  if (!request.nextUrl.pathname.startsWith(dashboardPath)) {
    return NextResponse.redirect(new URL(dashboardPath, request.url));
  }
  
  return NextResponse.next();
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
