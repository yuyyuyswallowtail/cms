# STEP 9 — Notification System

## 1. Notification Architecture

The notification system is database-backed with role-based targeting and real-time polling.

```
User Login → Check Notifications → Display Badge + List
                    ↓
Trigger Events:
- New Order → Notify Admins
- Payment Success → Notify Customer + Admins
- Low Stock → Notify Managers
- New User → Notify Admins
```

---

## 2. Notification Service (`src/services/NotificationService.ts`)

```typescript
// src/services/NotificationService.ts
import { db } from '@/lib/db';
import { NotificationType, NotificationTarget } from '@/types/enums';

export interface CreateNotificationInput {
  userId?: string;
  roleId?: string;
  targetType: NotificationTarget;
  type: NotificationType;
  title: string;
  message: string;
  data?: Record<string, any>;
}

export class NotificationService {
  async create(input: CreateNotificationInput): Promise<void> {
    const { userId, roleId, targetType, type, title, message, data } = input;

    await db.notification.create({
      data: {
        userId,
        roleId,
        targetType,
        type,
        title,
        message,
        data,
      },
    });
  }

  async createForUser(userId: string, type: NotificationType, title: string, message: string, data?: Record<string, any>) {
    return this.create({
      userId,
      targetType: NotificationTarget.USER,
      type,
      title,
      message,
      data,
    });
  }

  async createForRole(roleId: string, type: NotificationType, title: string, message: string, data?: Record<string, any>) {
    return this.create({
      roleId,
      targetType: NotificationTarget.ROLE,
      type,
      title,
      message,
      data,
    });
  }

  async createForAll(type: NotificationType, title: string, message: string, data?: Record<string, any>) {
    return this.create({
      targetType: NotificationTarget.ALL_USERS,
      type,
      title,
      message,
      data,
    });
  }

  async getForUser(userId: string, options: { limit?: number; unreadOnly?: boolean } = {}) {
    const { limit = 20, unreadOnly = false } = options;

    const where: any = {
      OR: [
        { userId },
        { targetType: NotificationTarget.ALL_USERS },
      ],
    };

    if (unreadOnly) {
      where.isRead = false;
    }

    return db.notification.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async getUnreadCount(userId: string): Promise<number> {
    return db.notification.count({
      where: {
        OR: [
          { userId },
          { targetType: NotificationTarget.ALL_USERS },
        ],
        isRead: false,
      },
    });
  }

  async markAsRead(notificationId: string, userId: string): Promise<void> {
    await db.notification.updateMany({
      where: {
        id: notificationId,
        userId,
      },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    });
  }

  async markAllAsRead(userId: string): Promise<void> {
    await db.notification.updateMany({
      where: {
        OR: [
          { userId },
          { targetType: NotificationTarget.ALL_USERS },
        ],
        isRead: false,
      },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    });
  }

  async delete(notificationId: string, userId: string): Promise<void> {
    await db.notification.delete({
      where: {
        id: notificationId,
        userId,
      },
    });
  }

  async clearAll(userId: string): Promise<void> {
    await db.notification.deleteMany({
      where: {
        OR: [
          { userId },
          { targetType: NotificationTarget.ALL_USERS },
        ],
      },
    });
  }

  // Trigger functions for common events
  async notifyNewOrder(orderId: string, orderNumber: string, amount: number) {
    // Get admin/manager roles
    const adminRoles = await db.role.findMany({
      where: {
        name: { in: ['SUPERADMIN', 'ADMIN', 'MANAGER'] },
      },
    });

    for (const role of adminRoles) {
      await this.createForRole(
        role.id,
        NotificationType.ORDER_CREATED,
        'New Order Received',
        `Order ${orderNumber} - Rp ${amount.toLocaleString('id-ID')}`,
        { orderId }
      );
    }
  }

  async notifyPaymentSuccess(orderId: string, orderNumber: string, userId: string) {
    await this.createForUser(
      userId,
      NotificationType.PAYMENT_SUCCESS,
      'Payment Successful',
      `Your payment for order ${orderNumber} has been confirmed`,
      { orderId }
    );

    // Also notify admins
    const adminRoles = await db.role.findMany({
      where: {
        name: { in: ['SUPERADMIN', 'ADMIN'] },
      },
    });

    for (const role of adminRoles) {
      await this.createForRole(
        role.id,
        NotificationType.PAYMENT_SUCCESS,
        'Payment Received',
        `Payment received for order ${orderNumber}`,
        { orderId }
      );
    }
  }

  async notifyPaymentFailed(orderId: string, orderNumber: string, userId: string) {
    await this.createForUser(
      userId,
      NotificationType.PAYMENT_FAILED,
      'Payment Failed',
      `Payment for order ${orderNumber} failed. Please try again.`,
      { orderId }
    );
  }

  async notifyNewUser(userId: string, userName: string, userEmail: string) {
    const adminRoles = await db.role.findMany({
      where: {
        name: { in: ['SUPERADMIN', 'ADMIN'] },
      },
    });

    for (const role of adminRoles) {
      await this.createForRole(
        role.id,
        NotificationType.NEW_USER,
        'New User Registration',
        `${userName} (${userEmail}) has registered`,
        { userId }
      );
    }
  }

  async notifyLowStock(productId: string, productName: string, currentStock: number) {
    const managerRoles = await db.role.findMany({
      where: {
        name: { in: ['SUPERADMIN', 'ADMIN', 'MANAGER'] },
      },
    });

    for (const role of managerRoles) {
      await this.createForRole(
        role.id,
        NotificationType.LOW_STOCK,
        'Low Stock Alert',
        `${productName} is running low (${currentStock} remaining)`,
        { productId }
      );
    }
  }

  async notifySystemAlert(title: string, message: string, severity: 'info' | 'warning' | 'critical' = 'info') {
    await this.createForAll(
      NotificationType.SYSTEM_ALERT,
      title,
      message,
      { severity }
    );
  }
}

export const notificationService = new NotificationService();
```

---

## 3. Notification API Routes

### 3.1 Get Notifications (`src/app/api/notifications/route.ts`)

```typescript
// src/app/api/notifications/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { notificationService } from '@/services/NotificationService';

export async function GET(request: NextRequest) {
  try {
    const userId = request.headers.get('x-user-id');
    
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '20');
    const unreadOnly = searchParams.get('unreadOnly') === 'true';

    const notifications = await notificationService.getForUser(userId, { limit, unreadOnly });
    const unreadCount = await notificationService.getUnreadCount(userId);

    return NextResponse.json({
      notifications,
      unreadCount,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const userId = request.headers.get('x-user-id');
    
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { action, notificationId } = body;

    if (action === 'markRead' && notificationId) {
      await notificationService.markAsRead(notificationId, userId);
    } else if (action === 'markAllRead') {
      await notificationService.markAllAsRead(userId);
    }

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const userId = request.headers.get('x-user-id');
    
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const notificationId = searchParams.get('id');

    if (notificationId) {
      await notificationService.delete(notificationId, userId);
    } else {
      await notificationService.clearAll(userId);
    }

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

---

## 4. Notification UI Components

### 4.1 Notification Bell (`src/components/notifications/NotificationBell.tsx`)

```typescript
// src/components/notifications/NotificationBell.tsx
'use client';

import { useEffect, useState } from 'react';
import { Bell, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn, formatDistanceToNow } from '@/lib/utils';

interface Notification {
  id: string;
  title: string;
  message: string;
  type: string;
  isRead: boolean;
  createdAt: string;
  data?: Record<string, any>;
}

export function NotificationBell() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    fetchNotifications();
    
    // Poll for new notifications every 30 seconds
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchNotifications = async () => {
    try {
      const res = await fetch('/api/notifications?limit=10');
      const data = await res.json();
      setNotifications(data.notifications);
      setUnreadCount(data.unreadCount);
    } catch (error) {
      console.error('Failed to fetch notifications:', error);
    }
  };

  const markAsRead = async (notificationId: string) => {
    try {
      await fetch('/api/notifications', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'markRead', notificationId }),
      });
      
      setNotifications((prev) =>
        prev.map((n) => (n.id === notificationId ? { ...n, isRead: true } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (error) {
      console.error('Failed to mark as read:', error);
    }
  };

  const markAllAsRead = async () => {
    try {
      await fetch('/api/notifications', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'markAllRead' }),
      });
      
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setUnreadCount(0);
    } catch (error) {
      console.error('Failed to mark all as read:', error);
    }
  };

  const getNotificationIcon = (type: string) => {
    // Different icons based on notification type
    return null;
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge
              className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-xs"
              variant="destructive"
            >
              {unreadCount > 9 ? '9+' : unreadCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="end">
        <div className="flex items-center justify-between p-4 border-b">
          <h3 className="font-semibold">Notifications</h3>
          {unreadCount > 0 && (
            <Button variant="ghost" size="sm" onClick={markAllAsRead}>
              <Check className="h-4 w-4 mr-1" />
              Mark all read
            </Button>
          )}
        </div>
        
        <ScrollArea className="h-80">
          {notifications.length === 0 ? (
            <div className="p-4 text-center text-muted-foreground">
              No notifications
            </div>
          ) : (
            <div className="divide-y">
              {notifications.map((notification) => (
                <div
                  key={notification.id}
                  className={cn(
                    'p-4 cursor-pointer hover:bg-muted/50 transition-colors',
                    !notification.isRead && 'bg-muted/30'
                  )}
                  onClick={() => !notification.isRead && markAsRead(notification.id)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className={cn(
                        'text-sm font-medium truncate',
                        !notification.isRead && 'font-semibold'
                      )}>
                        {notification.title}
                      </p>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {notification.message}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })}
                      </p>
                    </div>
                    {!notification.isRead && (
                      <div className="h-2 w-2 rounded-full bg-primary flex-shrink-0 mt-2" />
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
        
        <div className="p-2 border-t">
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => {
              setOpen(false);
              window.location.href = '/dashboard/notifications';
            }}
          >
            View all notifications
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
```

### 4.2 Notification List Page (`src/app/(dashboard)/notifications/page.tsx`)

```typescript
// src/app/(dashboard)/notifications/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Check, Trash2, Loader2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface Notification {
  id: string;
  title: string;
  message: string;
  type: string;
  isRead: boolean;
  createdAt: string;
  data?: Record<string, any>;
}

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'unread'>('all');

  useEffect(() => {
    fetchNotifications();
  }, [filter]);

  const fetchNotifications = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/notifications?unreadOnly=${filter === 'unread'}&limit=50`);
      const data = await res.json();
      setNotifications(data.notifications);
    } catch (error) {
      console.error('Failed to fetch:', error);
    } finally {
      setLoading(false);
    }
  };

  const markAsRead = async (id: string) => {
    await fetch('/api/notifications', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'markRead', notificationId: id }),
    });
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: true } : n))
    );
  };

  const markAllAsRead = async () => {
    await fetch('/api/notifications', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'markAllRead' }),
    });
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
  };

  const deleteNotification = async (id: string) => {
    await fetch(`/api/notifications?id=${id}`, { method: 'DELETE' });
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  const clearAll = async () => {
    await fetch('/api/notifications', { method: 'DELETE' });
    setNotifications([]);
  };

  return (
    <div className="container mx-auto py-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Notifications</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={markAllAsRead}>
            <Check className="h-4 w-4 mr-2" />
            Mark all read
          </Button>
          <Button variant="outline" onClick={clearAll}>
            <Trash2 className="h-4 w-4 mr-2" />
            Clear all
          </Button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 mb-4">
        <Button
          variant={filter === 'all' ? 'default' : 'ghost'}
          onClick={() => setFilter('all')}
        >
          All
        </Button>
        <Button
          variant={filter === 'unread' ? 'default' : 'ghost'}
          onClick={() => setFilter('unread')}
        >
          Unread
        </Button>
      </div>

      {/* Notifications List */}
      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      ) : notifications.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No notifications
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {notifications.map((notification) => (
            <Card
              key={notification.id}
              className={notification.isRead ? 'opacity-60' : ''}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{notification.title}</h3>
                      {!notification.isRead && (
                        <span className="h-2 w-2 rounded-full bg-primary" />
                      )}
                    </div>
                    <p className="text-muted-foreground mt-1">{notification.message}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      {formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })}
                    </p>
                  </div>
                  <div className="flex gap-1">
                    {!notification.isRead && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => markAsRead(notification.id)}
                      >
                        <Check className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => deleteNotification(notification.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
```

---

## 5. Notification Triggers Integration

### 5.1 Order Creation Trigger (in OrderService)

```typescript
// In OrderService after order creation
await notificationService.notifyNewOrder(
  order.id,
  order.orderNumber,
  Number(order.totalAmount)
);
```

### 5.2 Payment Webhook Trigger (in PaymentService)

```typescript
// In handleWebhook after payment success
await notificationService.notifyPaymentSuccess(
  order.id,
  order.orderNumber,
  order.userId
);
```

### 5.3 Low Stock Trigger (in ProductService)

```typescript
// After stock update
if (updatedProduct.stock <= updatedProduct.lowStockThreshold) {
  await notificationService.notifyLowStock(
    productId,
    updatedProduct.name,
    updatedProduct.stock
  );
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
