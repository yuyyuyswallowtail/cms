# STEP 5 — Payment Integration (Midtrans)

## 1. Payment Flow Overview

### 1.1 Order Creation Flow
```
1. User adds products to cart
2. User proceeds to checkout
3. User fills shipping details
4. User selects payment method
5. Server creates order with PENDING status
6. Server creates Midtrans payment token
7. Return Snap token to frontend
8. Frontend displays Midtrans Snap popup
9. User completes payment
10. Midtrans redirects to success/cancel page
11. Midtrans sends webhook notification
12. Server updates order/payment status
13. Server creates notification
14. Server invalidates cache
```

### 1.2 Payment Methods Supported
- Credit Card
- Bank Transfer (BNI, BRI, BCA, Mandiri, etc.)
- E-Wallet (GoPay, OVO, DANA, LinkAja)
- COD (Cash on Delivery)

---

## 2. Midtrans Integration

### 2.1 Midtrans Client (`src/lib/midtrans.ts`)

```typescript
// src/lib/midtrans.ts
import { CoreApi, Config, TransactionStatusResponse } from '@midtrans/server-sdk';
import crypto from 'crypto';

const isProduction = process.env.MIDTRANS_ENV === 'production';

const config: Config = {
  isProduction,
  serverKey: process.env.MIDTRANS_SERVER_KEY || '',
  clientKey: process.env.MIDTRANS_CLIENT_KEY || '',
};

export const midtransClient = new CoreApi(config);

// Helper to get Snap URL
export const SNAP_BASE_URL = isProduction
  ? 'https://app.midtrans.com/snap/v2'
  : 'https://app.sandbox.midtrans.com/snap/v2';

// Verify Midtrans signature
export function verifySignature(
  orderId: string,
  statusCode: string,
  grossAmount: string,
  signatureKey: string
): boolean {
  const mySignature = crypto
    .createHash('sha512')
    .update(orderId + statusCode + grossAmount + (process.env.MIDTRANS_SERVER_KEY || ''))
    .digest('hex');

  return mySignature === signatureKey;
}

// Map Midtrans transaction status to our PaymentStatus
export function mapPaymentStatus(
  transactionStatus: string
): 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'EXPIRED' | 'REFUNDED' {
  const statusMap: Record<string, any> = {
    'capture': 'COMPLETED',
    'settlement': 'COMPLETED',
    'pending': 'PENDING',
    'deny': 'FAILED',
    'expire': 'EXPIRED',
    'cancel': 'FAILED',
    'refund': 'REFUNDED',
    'partial_refund': 'REFUNDED',
  };
  return statusMap[transactionStatus] || 'PENDING';
}
```

### 2.2 Payment Service (`src/services/PaymentService.ts`)

```typescript
// src/services/PaymentService.ts
import { midtransClient, SNAP_BASE_URL, verifySignature, mapPaymentStatus } from '@/lib/midtrans';
import { db } from '@/lib/db';
import { cacheService } from './CacheService';
import { notificationService } from './NotificationService';
import { financialService } from './FinancialService';

const PAYMENT_EXPIRY_MINUTES = 24 * 60; // 24 hours

export interface CreatePaymentParams {
  orderId: string;
  paymentMethod: 'credit_card' | 'bank_transfer' | 'e_wallet' | 'c';
  customer: {
    name: string;
    email: string;
    phone: string;
  };
}

export class PaymentService {
  async createPaymentLink(params: CreatePaymentParams) {
    const { orderId, paymentMethod, customer } = params;

    // Get order
    const order = await db.order.findUnique({
      where: { id: orderId },
      include: {
        items: {
          include: { product: true },
        },
        payment: true,
      },
    });

    if (!order) {
      throw new Error('Order not found');
    }

    if (order.payment?.status === 'COMPLETED') {
      throw new Error('Order already paid');
    }

    // Build Midtrans transaction items
    const transactionItems = order.items.map((item) => ({
      id: item.productId,
      name: item.productName,
      price: Number(item.unitPrice),
      quantity: item.quantity,
    });

    // Add shipping cost if any
    if (Number(order.shippingCost) > 0) {
      transactionItems.push({
        id: 'shipping',
        name: 'Shipping Cost',
        price: Number(order.shippingCost),
        quantity: 1,
      });
    }

    // Build Snap API request
    const snapRequest = {
      transaction_details: {
        order_id: `ORD-${order.id.slice(0, 8)}-${Date.now()}`,
        gross_amount: Number(order.totalAmount),
        currency: order.currency,
      },
      customer_details: {
        first_name: customer.name.split(' ')[0],
        last_name: customer.name.split(' ').slice(1).join(' '),
        email: customer.email,
        phone: customer.phone,
        billing_address: {
          address: order.shippingAddress,
          city: order.shippingCity,
          postal_code: order.shippingPostalCode,
          country_code: 'IDN',
        },
        shipping_address: {
          address: order.shippingAddress,
          city: order.shippingCity,
          postal_code: order.shippingPostalCode,
          country_code: 'IDN',
        },
      },
      item_details: transactionItems,
      expiry: {
        start_time: new Date().toISOString(),
        duration: PAYMENT_EXPIRY_MINUTES,
        unit: 'minute',
      },
      custom_field1: order.id, // Our order ID
    };

    // Add payment method specific fields
    if (paymentMethod === 'bank_transfer') {
      snapRequest.bank_transfer = {
        bank: 'bni', // Default bank
      };
    } else if (paymentMethod === 'e_wallet') {
      snapRequest.echannel = {
        channel: 'gopay',
      };
    }

    // Create Snap token
    const snapResponse = await midtransClient.createTransactionToken(snapRequest);

    // Create/update payment record
    const payment = await db.payment.upsert({
      where: { orderId },
      create: {
        orderId,
        method: paymentMethod.toUpperCase().replace('_', '_') as any,
        amount: order.totalAmount,
        paymentToken: snapResponse.token,
        expireAt: new Date(Date.now() + PAYMENT_EXPIRY_MINUTES * 60 * 1000),
        midtransOrderId: snapRequest.transaction_details.order_id,
      },
      update: {
        paymentToken: snapResponse.token,
        expireAt: new Date(Date.now() + PAYMENT_EXPIRY_MINUTES * 60 * 1000),
        midtransOrderId: snapRequest.transaction_details.order_id,
      },
    });

    return {
      token: snapResponse.token,
      redirectUrl: `${SNAP_BASE_URL}/v2/token/${snapResponse.token}`,
      paymentId: payment.id,
      expiresAt: payment.expireAt,
    };
  }

  async handleWebhook(rawBody: any, signatureKey: string): Promise<void> {
    const {
      order_id,
      transaction_status,
      payment_type,
      gross_amount,
      status_code,
    } = rawBody;

    // Extract our order ID from custom_field
    const orderIdMatch = rawBody.custom_field1 || order_id.match(/ORD-([a-f0-9]+)/);
    const orderId = orderIdMatch?.[1] || orderIdMatch;

    if (!orderId) {
      console.error('Cannot extract order ID from webhook');
      throw new Error('Invalid order ID');
    }

    // Verify signature
    const isValidSignature = verifySignature(
      order_id,
      status_code,
      gross_amount,
      signatureKey
    );

    if (!isValidSignature) {
      console.error('Invalid webhook signature');
      throw new Error('Invalid signature');
    }

    // Check if already processed (idempotency)
    const existingPayment = await db.payment.findFirst({
      where: { midtransTransactionId: order_id },
    });

    if (existingPayment?.status === 'COMPLETED' && transaction_status === 'settlement') {
      console.log('Payment already processed:', order_id);
      return;
    }

    // Get order
    const order = await db.order.findUnique({
      where: { id: orderId },
      include: { payment: true },
    });

    if (!order) {
      throw new Error('Order not found');
    }

    // Update payment status
    const paymentStatus = mapPaymentStatus(transaction_status);

    await db.$transaction(async (tx) => {
      // Update payment
      await tx.payment.update({
        where: { id: order.payment!.id },
        data: {
          status: paymentStatus,
          midtransTransactionId: order_id,
          rawResponse: rawBody,
          paidAt: paymentStatus === 'COMPLETED' ? new Date() : null,
        },
      });

      // Update order status based on payment
      let orderStatus = order.status;
      if (paymentStatus === 'COMPLETED') {
        orderStatus = 'CONFIRMED';
      } else if (paymentStatus === 'EXPIRED') {
        orderStatus = 'CANCELLED';
      }

      await tx.order.update({
        where: { id: orderId },
        data: { status: orderStatus },
      });

      // Update product stock if payment completed
      if (paymentStatus === 'COMPLETED') {
        for (const item of order.items) {
          await tx.product.update({
            where: { id: item.productId },
            data: { stock: { decrement: item.quantity } },
          });
        }
      }
    });

    // Create notification
    if (paymentStatus === 'COMPLETED') {
      await notificationService.create({
        userId: order.userId,
        type: 'PAYMENT_SUCCESS',
        title: 'Payment Successful',
        message: `Your order ${order.orderNumber} has been paid successfully.`,
        data: { orderId: order.id },
      });

      // Update financial reports
      await financialService.updateReport(order.id);
    } else if (paymentStatus === 'FAILED') {
      await notificationService.create({
        userId: order.userId,
        type: 'PAYMENT_FAILED',
        title: 'Payment Failed',
        message: `Payment for order ${order.orderNumber} failed.`,
        data: { orderId: order.id },
      });
    }

    // Invalidate cache
    await cacheService.invalidate(`order:${orderId}`);
    await cacheService.invalidateDashboardCache();
  }

  async getPaymentStatus(orderId: string): Promise<string> {
    const payment = await db.payment.findUnique({
      where: { orderId },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    if (payment.status === 'COMPLETED') {
      return 'completed';
    }

    if (payment.expireAt && new Date() > payment.expireAt) {
      return 'expired';
    }

    return payment.status.toLowerCase();
  }

  async cancelPayment(orderId: string): Promise<void> {
    const payment = await db.payment.findUnique({
      where: { orderId },
    });

    if (!payment) {
      throw new Error('Payment not found');
    }

    if (payment.status === 'COMPLETED') {
      throw new Error('Cannot cancel completed payment');
    }

    try {
      // Call Midtrans to cancel
      await midtransClient.cancelTransaction(payment.midtransOrderId || '');
    } catch (error) {
      // May already be expired/cancelled on Midtrans
      console.error('Midtrans cancel error:', error);
    }

    await db.$transaction(async (tx) => {
      await tx.payment.update({
        where: { id: payment.id },
        data: { status: 'FAILED' },
      });

      await tx.order.update({
        where: { id: orderId },
        data: { status: 'CANCELLED' },
      });
    });
  }
}

export const paymentService = new PaymentService();
```

### 2.3 Webhook Handler (`src/app/api/webhooks/midtrans/route.ts`)

```typescript
// src/app/api/webhooks/midtrans/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { paymentService } from '@/services/PaymentService';
import { verifySignature } from '@/lib/midtrans';

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const signatureKey = request.headers.get('x-midtrans-signature') || '';

    // Parse JSON
    const body = JSON.parse(rawBody);

    // Verify signature
    const isValid = verifySignature(
      body.order_id,
      body.status_code,
      body.gross_amount,
      signatureKey
    );

    if (!isValid) {
      console.error('Invalid Midtrans signature');
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }

    // Process webhook
    await paymentService.handleWebhook(body, signatureKey);

    return NextResponse.json({ success: true });
  } catch (error: any) {
    console.error('Webhook error:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

---

## 3. Financial Reports

### 3.1 Financial Service (`src/services/FinancialService.ts`)

```typescript
// src/services/FinancialService.ts
import { db } from '@/lib/db';

export class FinancialService {
  async updateReport(orderId: string): Promise<void> {
    const order = await db.order.findUnique({
      where: { id: orderId },
      include: { payment: true },
    });

    if (!order || order.payment?.status !== 'COMPLETED') {
      return;
    }

    const period = new Date().toISOString().slice(0, 7); // YYYY-MM
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

    // Daily report
    await this.upsertReport(period, 'DAILY', today, Number(order.totalAmount), 1);

    // Monthly report
    await this.upsertReport(period, 'MONTHLY', period, Number(order.totalAmount), 1);
  }

  private async upsertReport(
    period: string,
    reportType: 'DAILY' | 'MONTHLY' | 'YEARLY',
    key: string,
    revenue: number,
    orders: number
  ): Promise<void> {
    const existing = await db.financialReport.findUnique({
      where: {
        period_reportType: { period: key, reportType },
      },
    });

    if (existing) {
      await db.financialReport.update({
        where: { id: existing.id },
        data: {
          revenue: { increment: revenue },
          orders: { increment: orders },
          averageOrderValue: undefined, // Will be recalculated
          netProfit: undefined,
        },
      });
    } else {
      await db.financialReport.create({
        data: {
          period: key,
          reportType,
          revenue,
          orders,
          averageOrderValue: revenue,
          netProfit: revenue, // Simplified - add expenses calculation
        },
      });
    }
  }

  async getReport(
    reportType: 'DAILY' | 'MONTHLY' | 'YEARLY',
    startDate: string,
    endDate: string
  ) {
    return db.financialReport.findMany({
      where: {
        reportType,
        period: {
          gte: startDate,
          lte: endDate,
        },
      },
      orderBy: { period: 'asc' },
    });
  }

  async getSummary() {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
    const startOfYear = new Date(now.getFullYear(), 0, 1).toISOString().slice(0, 10);

    const [monthly, yearly] = await Promise.all([
      db.financialReport.aggregate({
        where: {
          reportType: 'MONTHLY',
          period: { gte: startOfMonth },
        },
        _sum: { revenue: true, orders: true },
      }),
      db.financialReport.aggregate({
        where: {
          reportType: 'YEARLY',
          period: { gte: startOfYear },
        },
        _sum: { revenue: true, orders: true },
      }),
    ]);

    return {
      monthlyRevenue: monthly._sum.revenue || 0,
      monthlyOrders: monthly._sum.orders || 0,
      yearlyRevenue: yearly._sum.revenue || 0,
      yearlyOrders: yearly._sum.orders || 0,
    };
  }
}

export const financialService = new FinancialService();
```

---

## 4. CSV Export Utility

### 4.1 Export Service (`src/services/ExportService.ts`)

```typescript
// src/services/ExportService.ts
import { db } from '@/lib/db';

export class ExportService {
  async exportOrders(filters: {
    startDate?: string;
    endDate?: string;
    status?: string;
  }): Promise<string> {
    const where: any = {};

    if (filters.startDate || filters.endDate) {
      where.createdAt = {};
      if (filters.startDate) where.createdAt.gte = new Date(filters.startDate);
      if (filters.endDate) where.createdAt.lte = new Date(filters.endDate);
    }

    if (filters.status) {
      where.status = filters.status;
    }

    const orders = await db.order.findMany({
      where,
      include: {
        user: { select: { name: true, email: true } },
        items: { include: { product: { select: { name: true, sku: true } } } },
        payment: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    // Build CSV
    const headers = [
      'Order Number',
      'Date',
      'Customer Name',
      'Customer Email',
      'Status',
      'Items',
      'Subtotal',
      'Tax',
      'Shipping',
      'Total',
      'Payment Status',
      'Payment Method',
    ];

    const rows = orders.map((order) => [
      order.orderNumber,
      order.createdAt.toISOString(),
      order.customerName,
      order.customerEmail,
      order.status,
      order.items.map((i) => `${i.productName} x${i.quantity}`).join('; '),
      order.subtotal.toString(),
      order.taxAmount.toString(),
      order.shippingCost.toString(),
      order.totalAmount.toString(),
      order.payment?.status || 'N/A',
      order.payment?.method || 'N/A',
    ]);

    return this.toCSV(headers, rows);
  }

  async exportProducts(filters: {
    category?: string;
    status?: string;
  }): Promise<string> {
    const where: any = { deletedAt: null };

    if (filters.category) {
      where.category = { slug: filters.category };
    }

    if (filters.status) {
      where.status = filters.status;
    }

    const products = await db.product.findMany({
      where,
      include: {
        category: { select: { name: true } },
        images: { where: { isPrimary: true }, take: 1 },
      },
      orderBy: { createdAt: 'desc' },
    });

    const headers = [
      'Name',
      'SKU',
      'Category',
      'Price',
      'Stock',
      'Status',
      'Featured',
      'Created At',
    ];

    const rows = products.map((p) => [
      p.name,
      p.sku || '',
      p.category?.name || 'Uncategorized',
      p.price.toString(),
      p.stock.toString(),
      p.status,
      p.featured ? 'Yes' : 'No',
      p.createdAt.toISOString(),
    ]);

    return this.toCSV(headers, rows);
  }

  async exportFinancialReport(
    reportType: 'DAILY' | 'MONTHLY' | 'YEARLY',
    startDate: string,
    endDate: string
  ): Promise<string> {
    const reports = await db.financialReport.findMany({
      where: {
        reportType,
        period: { gte: startDate, lte: endDate },
      },
      orderBy: { period: 'asc' },
    });

    const headers = ['Period', 'Revenue', 'Orders', 'Average Order Value', 'Net Profit'];

    const rows = reports.map((r) => [
      r.period,
      r.revenue.toString(),
      r.orders.toString(),
      r.averageOrderValue.toString(),
      r.netProfit.toString(),
    ]);

    return this.toCSV(headers, rows);
  }

  private toCSV(headers: string[], rows: string[][]): string {
    const escapeCell = (cell: string) => {
      if (cell.includes(',') || cell.includes('"') || cell.includes('\n')) {
        return `"${cell.replace(/"/g, '""')}"`;
      }
      return cell;
    };

    const headerRow = headers.map(escapeCell).join(',');
    const dataRows = rows.map((row) => row.map(escapeCell).join(','));

    return [headerRow, ...dataRows].join('\n');
  }
}

export const exportService = new ExportService();
```

### 4.2 Export API Route (`src/app/api/export/orders/route.ts`)

```typescript
// src/app/api/export/orders/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { exportService } from '@/services/ExportService';
import { requirePermission } from '@/middleware/rbac';

export async function GET(request: NextRequest) {
  // Check permission
  const authCheck = await requirePermission('orders.read')(request);
  if (authCheck) return authCheck;

  try {
    const { searchParams } = new URL(request.url);
    const startDate = searchParams.get('startDate') || undefined;
    const endDate = searchParams.get('endDate') || undefined;
    const status = searchParams.get('status') || undefined;

    const csv = await exportService.exportOrders({ startDate, endDate, status });

    return new NextResponse(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="orders-${new Date().toISOString().slice(0, 10)}.csv"`,
      },
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

---

## 5. Transaction Safety

### 5.1 Idempotency Handling
```typescript
// In webhook handler - check if already processed
const existingPayment = await db.payment.findFirst({
  where: { midtransTransactionId: order_id },
});

if (existingPayment?.status === 'COMPLETED' && transaction_status === 'settlement') {
  return NextResponse.json({ success: true, message: 'Already processed' });
}
```

### 5.2 Race Condition Prevention
```typescript
// Use database transactions
await db.$transaction(async (tx) => {
  // Lock order row
  const order = await tx.order.findUnique({ where: { id: orderId } });
  
  // Update payment
  await tx.payment.update({...});
  
  // Update order
  await tx.order.update({...});
});
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
