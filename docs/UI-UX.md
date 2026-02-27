# STEP 8 — UI/UX Implementation

## 1. Layout Structure

### 1.1 Root Layout (`src/app/layout.tsx`)

```typescript
// src/app/layout.tsx
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';
import { ThemeProvider } from '@/components/providers/theme-provider';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: {
    default: 'CMS - Company Profile',
    template: '%s | CMS',
  },
  description: 'Enterprise CMS for Company Profile Management',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <Providers>{children}</Providers>
        </ThemeProvider>
      </body>
    </html>
  );
}
```

### 1.2 CMS Layout (`src/app/(cms)/layout.tsx`)

```typescript
// src/app/(cms)/layout.tsx
import { Header } from '@/components/layout/Header';
import { Footer } from '@/components/layout/Footer';

export default function CMSLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col">
      <Header />
      <main className="flex-1">{children}</main>
      <Footer />
    </div>
  );
}
```

### 1.3 Dashboard Layout (`src/app/(dashboard)/layout.tsx`)

```typescript
// src/app/(dashboard)/layout.tsx
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
```

---

## 2. Sidebar Architecture

### 2.1 Sidebar Component (`src/components/layout/Sidebar.tsx`)

```typescript
// src/components/layout/Sidebar.tsx
'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { 
  LayoutDashboard, 
  Package, 
  ShoppingCart, 
  FileText, 
  Users, 
  Settings, 
  BarChart3,
  CreditCard,
  Bell,
  Layers,
  MessageSquare,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';

interface NavItem {
  title: string;
  href: string;
  icon: React.ElementType;
  roles?: string[];
}

const navItems: NavItem[] = [
  { title: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { title: 'Orders', href: '/dashboard/orders', icon: ShoppingCart },
  { title: 'Products', href: '/dashboard/products', icon: Package },
  { title: 'Categories', href: '/dashboard/categories', icon: Layers },
  { title: 'Services', href: '/dashboard/services', icon: FileText },
  { title: 'Articles', href: '/dashboard/articles', icon: FileText },
  { title: 'Customers', href: '/dashboard/customers', icon: Users },
  { title: 'Reports', href: '/dashboard/reports', icon: BarChart3 },
  { title: 'Payments', href: '/dashboard/payments', icon: CreditCard },
  { title: 'Testimonials', href: '/dashboard/testimonials', icon: MessageSquare },
  { title: 'Notifications', href: '/dashboard/notifications', icon: Bell },
  { title: 'Settings', href: '/dashboard/settings', icon: Settings, roles: ['SUPERADMIN', 'ADMIN'] },
];

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        'flex flex-col border-r bg-card transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center justify-between border-b px-4">
        {!collapsed && (
          <Link href="/dashboard" className="text-xl font-bold">
            CMS
          </Link>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className={cn(collapsed && 'mx-auto')}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-2 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                collapsed && 'justify-center px-2'
              )}
              title={collapsed ? item.title : undefined}
            >
              <item.icon className="h-5 w-5 flex-shrink-0" />
              {!collapsed && <span>{item.title}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t p-4">
        {!collapsed && (
          <p className="text-xs text-muted-foreground">© 2026 CMS</p>
        )}
      </div>
    </aside>
  );
}
```

---

## 3. Protected Route Handling

### 3.1 Auth Guard Component (`src/components/auth/AuthGuard.tsx`)

```typescript
// src/components/auth/AuthGuard.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { Loader2 } from 'lucide-react';

interface AuthGuardProps {
  children: React.ReactNode;
  requiredRoles?: string[];
}

export function AuthGuard({ children, requiredRoles = [] }: AuthGuardProps) {
  const router = useRouter();
  const pathname = usePathname();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/me');
        
        if (!res.ok) {
          router.push(`/login?redirect=${pathname}`);
          return;
        }

        const user = await res.json();

        if (requiredRoles.length > 0 && !requiredRoles.includes(user.role)) {
          router.push('/dashboard/unauthorized');
          return;
        }
      } catch (error) {
        router.push(`/login?redirect=${pathname}`);
      } finally {
        setChecking(false);
      }
    }

    checkAuth();
  }, [pathname, router, requiredRoles]);

  if (checking) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return <>{children}</>;
}
```

### 3.2 Protected Route Wrapper (`src/components/auth/ProtectedRoute.tsx`)

```typescript
// src/components/auth/ProtectedRoute.tsx
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export async function ProtectedRoute({
  children,
  roles = [],
}: {
  children: React.ReactNode;
  roles?: string[];
}) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get('session_token');

  if (!sessionToken) {
    redirect('/login');
  }

  // In a real app, validate session and check roles
  // For now, we'll let client-side handle this

  return <>{children}</>;
}
```

---

## 4. Animation Strategy (Framer Motion)

### 4.1 Page Transitions (`src/components/ui/PageTransition.tsx`)

```typescript
// src/components/ui/PageTransition.tsx
'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { usePathname } from 'next/navigation';

interface PageTransitionProps {
  children: React.ReactNode;
}

export function PageTransition({ children }: PageTransitionProps) {
  const pathname = usePathname();

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={pathname}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        transition={{ duration: 0.2 }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
```

### 4.2 Fade In Component (`src/components/ui/FadeIn.tsx`)

```typescript
// src/components/ui/FadeIn.tsx
'use client';

import { motion, HTMLMotionProps } from 'framer-motion';
import { cn } from '@/lib/utils';

interface FadeInProps extends HTMLMotionProps<'div'> {
  delay?: number;
  direction?: 'up' | 'down' | 'left' | 'right';
}

export function FadeIn({
  children,
  delay = 0,
  direction = 'up',
  className,
  ...props
}: FadeInProps) {
  const directions = {
    up: { y: 20, x: 0 },
    down: { y: -20, x: 0 },
    left: { x: 20, y: 0 },
    right: { x: -20, y: 0 },
  };

  return (
    <motion.div
      initial={{ opacity: 0, ...directions[direction] }}
      animate={{ opacity: 1, x: 0, y: 0 }}
      transition={{ duration: 0.3, delay, ease: 'easeOut' }}
      className={cn(className)}
      {...props}
    >
      {children}
    </motion.div>
  );
}
```

### 4.3 List Animation (`src/components/ui/StaggerContainer.tsx`)

```typescript
// src/components/ui/StaggerContainer.tsx
'use client';

import { motion } from 'framer-motion';
import { HTMLMotionProps } from 'framer-motion';

interface StaggerContainerProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
  staggerDelay?: number;
}

export function StaggerContainer({
  children,
  staggerDelay = 0.05,
  className,
  ...props
}: StaggerContainerProps) {
  return (
    <motion.div
      initial="initial"
      animate="animate"
      variants={{
        initial: {},
        animate: {
          transition: {
            staggerChildren: staggerDelay,
          },
        },
      }}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export const staggerItem = {
  initial: { opacity: 0, y: 10 },
  animate: { 
    opacity: 1, 
    y: 0,
    transition: { duration: 0.3 }
  },
};
```

---

## 5. Toast Notification System

### 5.1 Toast Hook (`src/hooks/useToast.ts`)

```typescript
// src/hooks/useToast.ts
import { useState, useCallback } from 'react';

export interface Toast {
  id: string;
  title: string;
  description?: string;
  variant?: 'default' | 'success' | 'error' | 'warning';
  duration?: number;
}

let toastId = 0;

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((options: Omit<Toast, 'id'>) => {
    const id = String(++toastId);
    const newToast: Toast = { id    
    setToasts((prev), ...options };
 => [...prev, newToast]);

    // Auto dismiss
    const duration = options.duration || 5000;
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, duration);

    return id;
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const dismissAll = useCallback(() => {
    setToasts([]);
  }, []);

  return {
    toast,
    dismiss,
    dismissAll,
    toasts,
  };
}
```

### 5.2 Toast Provider (`src/components/providers/ToastProvider.tsx`)

```typescript
// src/components/providers/ToastProvider.tsx
'use client';

import { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';

interface Toast {
  id: string;
  title: string;
  description?: string;
  variant?: 'default' | 'success' | 'error' | 'warning';
}

interface ToastContextType {
  toast: (options: Omit<Toast, 'id'>) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return context;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((options: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev, { id, ...options }]);

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast, dismiss }}>
      {children}
      
      {/* Toast Container */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
        <AnimatePresence>
          {toasts.map((t) => (
            <ToastItem key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const variants = {
    default: 'bg-background border',
    success: 'bg-green-500 text-white',
    error: 'bg-red-500 text-white',
    warning: 'bg-yellow-500 text-white',
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 50 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 50 }}
      className={cn(
        'flex items-start gap-3 rounded-lg p-4 shadow-lg',
        variants[toast.variant || 'default']
      )}
    >
      <div className="flex-1">
        <p className="font-medium">{toast.title}</p>
        {toast.description && (
          <p className="text-sm opacity-90">{toast.description}</p>
        )}
      </div>
      <button onClick={onDismiss} className="opacity-70 hover:opacity-100">
        <X className="h-4 w-4" />
      </button>
    </motion.div>
  );
}
```

---

## 6. Skeleton Loading

### 6.1 Skeleton Components (`src/components/ui/Skeleton.tsx`)

```typescript
// src/components/ui/Skeleton.tsx
import { cn } from '@/lib/utils';

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-muted', className)}
      {...props}
    />
  );
}

// Pre-defined skeletons
function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      <Skeleton className="h-10 w-full" />
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  );
}

function CardSkeleton() {
  return (
    <div className="rounded-lg border p-4 space-y-3">
      <Skeleton className="h-6 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-2/3" />
    </div>
  );
}

function FormSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-4 w-1/4" />
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-4 w-1/4" />
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-10 w-1/3" />
    </div>
  );
}

export { Skeleton, TableSkeleton, CardSkeleton, FormSkeleton };
```

---

## 7. Optimistic UI Updates

### 7.1 Optimistic Update Hook (`src/hooks/useOptimisticUpdate.ts`)

```typescript
// src/hooks/useOptimisticUpdate.ts
import { useState, useCallback } from 'react';

interface OptimisticState<T> {
  data: T;
  isPending: boolean;
  error: Error | null;
}

export function useOptimisticUpdate<T>(
  initialData: T,
  updateFn: (newData: T) => Promise<T>
) {
  const [state, setState] = useState<OptimisticState<T>>({
    data: initialData,
    isPending: false,
    error: null,
  });

  const update = useCallback(async (newData: T, rollbackData?: T) => {
    // Optimistically update
    setState((prev) => ({ ...prev, data: newData, isPending: true, error: null }));

    try {
      const result = await updateFn(newData);
      setState({ data: result, isPending: false, error: null });
    } catch (error) {
      // Rollback on error
      setState({
        data: rollbackData || state.data,
        isPending: false,
        error: error as Error,
      });
    }
  }, [updateFn, state.data]);

  return { ...state, update };
}
```

---

## 8. Theme Support

### 8.1 Theme Toggle (`src/components/theme/ThemeToggle.tsx`)

```typescript
// src/components/theme/ThemeToggle.tsx
'use client';

import { useTheme } from 'next-themes';
import { Moon, Sun, Monitor } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

export function ThemeToggle() {
  const { setTheme, theme } = useTheme();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <Sun className="h-5 w-5 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-5 w-5 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setTheme('light')}>
          <Sun className="mr-2 h-4 w-4" />
          Light
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('dark')}>
          <Moon className="mr-2 h-4 w-4" />
          Dark
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('system')}>
          <Monitor className="mr-2 h-4 w-4" />
          System
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
```

---

## 9. Accessibility Considerations

### 9.1 Keyboard Navigation
- All interactive elements focusable
- Proper tab order
- Skip to main content link
- Focus visible indicators

### 9.2 Screen Reader Support
- Semantic HTML
- ARIA labels where needed
- Proper heading hierarchy

### 9.3 Color Contrast
- WCAG AA compliant
- Never use color alone for information

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
