# STEP 6 — CMS Features Implementation

## 1. Markdown Article System

### 1.1 Article Service (`src/services/ArticleService.ts`)

```typescript
// src/services/ArticleService.ts
import { db } from '@/lib/db';
import { cacheService } from './CacheService';
import { ArticleStatus } from '@/types/enums';

export interface CreateArticleInput {
  title: string;
  slug?: string;
  content: string;
  excerpt?: string;
  coverImage?: string;
  author?: string;
  status?: ArticleStatus;
  tagIds?: string[];
}

export interface ArticleFilters {
  status?: ArticleStatus;
  tagId?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export class ArticleService {
  private generateSlug(title: string): string {
    return title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');
  }

  async create(input: CreateArticleInput, authorId: string) {
    const slug = input.slug || this.generateSlug(input.title);

    // Check slug uniqueness
    const existing = await db.article.findUnique({ where: { slug } });
    if (existing) {
      throw new Error('Slug already exists');
    }

    const article = await db.$transaction(async (tx) => {
      const created = await tx.article.create({
        data: {
          title: input.title,
          slug,
          content: input.content,
          excerpt: input.excerpt,
          coverImage: input.coverImage,
          author: input.author,
          status: input.status || ArticleStatus.DRAFT,
          publishedAt: input.status === ArticleStatus.PUBLISHED ? new Date() : null,
        },
      });

      // Add tags
      if (input.tagIds?.length) {
        await tx.articleTag.createMany({
          data: input.tagIds.map((tagId) => ({
            articleId: created.id,
            tagId,
          })),
        });
      }

      return created;
    });

    // Invalidate cache
    await cacheService.invalidatePattern('article:*');

    return article;
  }

  async update(id: string, input: Partial<CreateArticleInput>) {
    const updateData: any = { ...input };

    // Handle slug
    if (input.title && !input.slug) {
      updateData.slug = this.generateSlug(input.title);
    }

    // Handle published status
    if (input.status === ArticleStatus.PUBLISHED) {
      updateData.publishedAt = new Date();
    }

    const article = await db.$transaction(async (tx) => {
      const updated = await tx.article.update({
        where: { id },
        data: updateData,
      });

      // Update tags if provided
      if (input.tagIds !== undefined) {
        await tx.articleTag.deleteMany({ where: { articleId: id } });
        
        if (input.tagIds.length) {
          await tx.articleTag.createMany({
            data: input.tagIds.map((tagId) => ({
              articleId: id,
              tagId,
            })),
          });
        }
      }

      return updated;
    });

    await cacheService.invalidatePattern('article:*');
    return article;
  }

  async delete(id: string) {
    const article = await db.article.softDelete({ where: { id } });
    await cacheService.invalidatePattern('article:*');
    return article;
  }

  async restore(id: string) {
    const article = await db.article.update({
      where: { id },
      data: { deletedAt: null },
    });
    await cacheService.invalidatePattern('article:*');
    return article;
  }

  async findById(id: string) {
    return db.article.findUnique({
      where: { id },
      include: {
        tags: { include: { tag: true } },
      },
    });
  }

  async findBySlug(slug: string) {
    // Increment view count
    await db.article.updateMany({
      where: { slug },
      data: { viewCount: { increment: 1 } },
    });

    return db.article.findUnique({
      where: { slug },
      include: {
        tags: { include: { tag: true } },
      },
    });
  }

  async findAll(filters: ArticleFilters = {}) {
    const { status, tagId, search, page = 1, limit = 10 } = filters;

    const where: any = {
      deletedAt: null,
    };

    if (status) {
      where.status = status;
    }

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { content: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (tagId) {
      where.tags = { some: { tagId } };
    }

    const [articles, total] = await Promise.all([
      db.article.findMany({
        where,
        include: {
          tags: { include: { tag: true } },
        },
        orderBy: { publishedAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      db.article.count({ where }),
    ]);

    return {
      articles,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }
}

export const articleService = new ArticleService();
```

### 1.2 Markdown Renderer Component (`src/components/shared/MarkdownRenderer.tsx`)

```typescript
// src/components/shared/MarkdownRenderer.tsx
'use client';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

export function MarkdownRenderer({ content, className = '' }: MarkdownRendererProps) {
  return (
    <div className={`prose prose-sm max-w-none ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          code({ node, inline, className, children, ...props }: any) {
            const match = /language-(\w+)/.exec(className || '');
            return !inline && match ? (
              <SyntaxHighlighter
                style={oneDark}
                language={match[1]}
                PreTag="div"
                {...props}
              >
                {String(children).replace(/\n$/, '')}
              </SyntaxHighlighter>
            ) : (
              <code className={className} {...props}>
                {children}
              </code>
            );
          },
          img({ src, alt }) {
            return (
              <img
                src={src}
                alt={alt}
                className="max-w-full h-auto rounded-lg"
                loading="lazy"
              />
            );
          },
          a({ href, children }) {
            return (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline"
              >
                {children}
              </a>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
```

### 1.3 Markdown Editor (`src/components/shared/MarkdownEditor.tsx`)

```typescript
// src/components/shared/MarkdownEditor.tsx
'use client';

import { useState, useCallback } from 'react';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { MarkdownRenderer } from './MarkdownRenderer';

interface MarkdownEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  minHeight?: string;
}

export function MarkdownEditor({
  value,
  onChange,
  placeholder = 'Write your content in Markdown...',
  minHeight = '300px',
}: MarkdownEditorProps) {
  const [mode, setMode] = useState<'write' | 'preview'>('write');

  const insertMarkdown = useCallback((syntax: string, wrap: boolean = false) => {
    const textarea = document.querySelector('textarea') as HTMLTextAreaElement;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selectedText = value.substring(start, end);

    let newText: string;
    let newCursorPos: number;

    if (wrap && selectedText) {
      newText = value.substring(0, start) + syntax + selectedText + syntax + value.substring(end);
      newCursorPos = end + syntax.length * 2;
    } else {
      newText = value.substring(0, start) + syntax + value.substring(end);
      newCursorPos = start + syntax.length;
    }

    onChange(newText);
    
    // Restore cursor position
    setTimeout(() => {
      textarea.focus();
      textarea.setSelectionRange(newCursorPos, newCursorPos);
    }, 0);
  }, [value, onChange]);

  return (
    <div className="border rounded-lg overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-1 p-2 bg-muted border-b">
        <Button
          type="button"
          variant={mode === 'write' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setMode('write')}
        >
          Write
        </Button>
        <Button
          type="button"
          variant={mode === 'preview' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setMode('preview')}
        >
          Preview
        </Button>

        <div className="flex-1" />

        {/* Markdown shortcuts */}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('**', true)}
        >
          B
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('*', true)}
        >
          I
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('# ')}
        >
          H1
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('## ')}
        >
          H2
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('[](')}
        >
          Link
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('![alt](')}
        >
          Img
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => insertMarkdown('```\n', false)}
        >
          Code
        </Button>
      </div>

      {/* Editor / Preview */}
      {mode === 'write' ? (
        <Textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          style={{ minHeight }}
          className="border-0 rounded-none focus-visible:ring-0"
        />
      ) : (
        <div className="p-4" style={{ minHeight }}>
          {value ? (
            <MarkdownRenderer content={value} />
          ) : (
            <p className="text-muted-foreground">Nothing to preview</p>
          )}
        </div>
      )}
    </div>
  );
}
```

---

## 2. Product Management

### 2.1 Product Service (`src/services/ProductService.ts`)

```typescript
// src/services/ProductService.ts
import { db } from '@/lib/db';
import { cacheService } from './CacheService';
import { ProductStatus } from '@/types/enums';

export interface ProductFilters {
  search?: string;
  categoryId?: string;
  status?: ProductStatus;
  featured?: boolean;
  minPrice?: number;
  maxPrice?: number;
  page?: number;
  limit?: number;
  sort?: 'name_asc' | 'name_desc' | 'price_asc' | 'price_desc' | 'newest' | 'oldest';
}

export class ProductService {
  async create(data: {
    name: string;
    slug?: string;
    description?: string;
    price: number;
    costPrice?: number;
    stock?: number;
    sku?: string;
    categoryId?: string;
    status?: ProductStatus;
    featured?: boolean;
    images?: { url: string; altText?: string; isPrimary?: boolean }[];
  }) {
    const slug = data.slug || data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    const product = await db.$transaction(async (tx) => {
      const created = await tx.product.create({
        data: {
          ...data,
          slug,
          status: data.status || ProductStatus.DRAFT,
        },
      });

      if (data.images?.length) {
        await tx.productImage.createMany({
          data: data.images.map((img, index) => ({
            productId: created.id,
            url: img.url,
            altText: img.altText,
            isPrimary: img.isPrimary ?? index === 0,
            sortOrder: index,
          })),
        });
      }

      return created;
    });

    await cacheService.invalidateProductCache();
    return product;
  }

  async update(id: string, data: Partial<{
    name: string;
    slug: string;
    description: string;
    price: number;
    costPrice: number;
    stock: number;
    sku: string;
    categoryId: string;
    status: ProductStatus;
    featured: boolean;
  }>) {
    const product = await db.product.update({
      where: { id },
      data,
    });

    await cacheService.invalidateProductCache(id);
    return product;
  }

  async delete(id: string) {
    const product = await db.product.update({
      where: { id },
      data: { deletedAt: new Date() },
    });

    await cacheService.invalidateProductCache(id);
    return product;
  }

  async restore(id: string) {
    const product = await db.product.update({
      where: { id },
      data: { deletedAt: null },
    });

    await cacheService.invalidateProductCache(id);
    return product;
  }

  async findById(id: string) {
    return db.product.findUnique({
      where: { id },
      include: {
        category: true,
        images: { orderBy: { sortOrder: 'asc' } },
      },
    });
  }

  async findBySlug(slug: string) {
    return db.product.findUnique({
      where: { slug },
      include: {
        category: true,
        images: { orderBy: { sortOrder: 'asc' } },
      },
    });
  }

  async findAll(filters: ProductFilters = {}) {
    const {
      search,
      categoryId,
      status,
      featured,
      minPrice,
      maxPrice,
      page = 1,
      limit = 10,
      sort = 'newest',
    } = filters;

    const where: any = { deletedAt: null };

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { sku: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (categoryId) {
      where.categoryId = categoryId;
    }

    if (status) {
      where.status = status;
    }

    if (featured !== undefined) {
      where.featured = featured;
    }

    if (minPrice !== undefined || maxPrice !== undefined) {
      where.price = {};
      if (minPrice !== undefined) where.price.gte = minPrice;
      if (maxPrice !== undefined) where.price.lte = maxPrice;
    }

    // Sort mapping
    const orderBy: any = {};
    switch (sort) {
      case 'name_asc':
        orderBy.name = 'asc';
        break;
      case 'name_desc':
        orderBy.name = 'desc';
        break;
      case 'price_asc':
        orderBy.price = 'asc';
        break;
      case 'price_desc':
        orderBy.price = 'desc';
        break;
      case 'oldest':
        orderBy.createdAt = 'asc';
        break;
      default:
        orderBy.createdAt = 'desc';
    }

    const [products, total] = await Promise.all([
      db.product.findMany({
        where,
        include: {
          category: true,
          images: { where: { isPrimary: true }, take: 1 },
        },
        orderBy,
        skip: (page - 1) * limit,
        take: limit,
      }),
      db.product.count({ where }),
    ]);

    return {
      products,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async updateStock(id: string, quantity: number) {
    return db.product.update({
      where: { id },
      data: { stock: { increment: quantity } },
    });
  }
}

export const productService = new ProductService();
```

---

## 3. Reusable Data Table Component

### 3.1 Data Table Types (`src/components/shared/DataTable/types.ts`)

```typescript
// src/components/shared/DataTable/types.ts
import { ColumnDef } from '@tanstack/react-table';

export interface DataTableColumnDef<TData, TValue> extends ColumnDef<TData, TValue> {
  enableSorting?: boolean;
  enableFiltering?: boolean;
  filterVariant?: 'text' | 'select' | 'range' | 'date';
  filterOptions?: { label: string; value: string }[];
}

export interface DataTablePaginationState {
  pageIndex: number;
  pageSize: number;
}

export interface DataTableSortState {
  id: string;
  desc: boolean;
}

export interface DataTableFilterState {
  [key: string]: string | string[] | number | [number, number];
}

export interface DataTableResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}
```

### 3.2 Data Table Component (`src/components/shared/DataTable/DataTable.tsx`)

```typescript
// src/components/shared/DataTable/DataTable.tsx
'use client';

import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
  getPaginationRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  SortingState,
  PaginationState,
  Row,
} from '@tanstack/react-table';
import { useState, useCallback } from 'react';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  pageCount: number;
  pageIndex: number;
  pageSize: number;
  total: number;
  onPaginationChange?: (pageIndex: number, pageSize: number) => void;
  onRowClick?: (row: TData) => void;
  rowSelection?: Record<string, boolean>;
  onRowSelectionChange?: (selection: Record<string, boolean>) => void;
  enableSelection?: boolean;
  loading?: boolean;
}

export function DataTable<TData, TValue>({
  columns,
  data,
  pageCount,
  pageIndex,
  pageSize,
  total,
  onPaginationChange,
  onRowClick,
  rowSelection = {},
  onRowSelectionChange,
  enableSelection = false,
  loading = false,
}: DataTableProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);

  const table = useReactTable({
    data,
    columns,
    pageCount,
    state: {
      sorting,
      rowSelection,
      pagination: { pageIndex, pageSize },
    },
    onSortingChange: setSorting,
    onRowSelectionChange: (updater) => {
      if (typeof updater === 'function') {
        onRowSelectionChange?.(updater(rowSelection));
      }
    },
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    manualPagination: true,
    onPaginationChange: (updater) => {
      if (typeof updater === 'function') {
        const newState = updater({ pageIndex, pageSize });
        onPaginationChange?.(newState.pageIndex, newState.pageSize);
      }
    },
  });

  const handlePageChange = (newPageIndex: number, newPageSize: number) => {
    onPaginationChange?.(newPageIndex, newPageSize);
  };

  return (
    <div className="space-y-4">
      {/* Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                    {header.column.getCanSort() && (
                      <button
                        className="ml-2 inline-flex"
                        onClick={() => header.column.toggleSorting()}
                      >
                        {{
                          asc: <ArrowUp className="h-4 w-4" />,
                          desc: <ArrowDown className="h-4 w-4" />,
                        }[header.column.getIsSorted() as string] ?? (
                          <ArrowUpDown className="h-4 w-4 opacity-50" />
                        )}
                      </button>
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="h-24 text-center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() && 'selected'}
                  className={onRowClick ? 'cursor-pointer hover:bg-muted/50' : ''}
                  onClick={() => onRowClick?.(row.original)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="h-24 text-center">
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">
            Page {pageIndex + 1} of {pageCount}
          </span>
          <Select
            value={pageSize.toString()}
            onValueChange={(value) => handlePageChange(0, parseInt(value))}
          >
            <SelectTrigger className="h-8 w-[70px]">
              <SelectValue placeholder={pageSize} />
            </SelectTrigger>
            <SelectContent side="top">
              {[10, 20, 50, 100].map((size) => (
                <SelectItem key={size} value={size.toString()}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handlePageChange(0, pageSize)}
            disabled={pageIndex === 0}
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handlePageChange(pageIndex - 1, pageSize)}
            disabled={pageIndex === 0}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handlePageChange(pageIndex + 1, pageSize)}
            disabled={pageIndex >= pageCount - 1}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handlePageChange(pageCount - 1, pageSize)}
            disabled={pageIndex >= pageCount - 1}
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
```

### 3.3 Usage Example (`src/app/(dashboard)/products/page.tsx`)

```typescript
// src/app/(dashboard)/products/page.tsx
'use client';

import { ColumnDef } from '@tanstack/react-table';
import { DataTable } from '@/components/shared/DataTable/DataTable';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Button } from '@/components/ui/button';
import { MoreHorizontal, Pencil, Trash, Eye } from 'lucide-react';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { ProductStatus } from '@/types/enums';

interface Product {
  id: string;
  name: string;
  sku: string;
  price: number;
  stock: number;
  status: ProductStatus;
  category?: string;
}

const columns: ColumnDef<Product>[] = [
  {
    id: 'select',
    header: ({ table }) => (
      <Checkbox
        checked={table.getIsAllPageRowsSelected()}
        onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
        aria-label="Select all"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(value) => row.toggleSelected(!!value)}
        aria-label="Select row"
      />
    ),
    enableSorting: false,
  },
  {
    accessorKey: 'name',
    header: 'Name',
    cell: ({ row }) => <span className="font-medium">{row.getValue('name')}</span>,
  },
  {
    accessorKey: 'sku',
    header: 'SKU',
  },
  {
    accessorKey: 'price',
    header: 'Price',
    cell: ({ row }) => {
      const price = parseFloat(row.getValue('price'));
      return new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR' }).format(price);
    },
  },
  {
    accessorKey: 'stock',
    header: 'Stock',
    cell: ({ row }) => {
      const stock = row.getValue('stock') as number;
      return (
        <Badge variant={stock > 10 ? 'default' : stock > 0 ? 'warning' : 'destructive'}>
          {stock}
        </Badge>
      );
    },
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const status = row.getValue('status') as string;
      return (
        <Badge variant={status === 'PUBLISHED' ? 'default' : 'secondary'}>
          {status}
        </Badge>
      );
    },
  },
  {
    id: 'actions',
    cell: ({ row }) => {
      const product = row.original;
      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => window.location.href = `/products/${product.id}`}>
              <Eye className="mr-2 h-4 w-4" /> View
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => window.location.href = `/products/${product.id}/edit`}>
              <Pencil className="mr-2 h-4 w-4" /> Edit
            </DropdownMenuItem>
            <DropdownMenuItem className="text-red-600">
              <Trash className="mr-2 h-4 w-4" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      );
    },
  },
];

export default function ProductsPage() {
  const [products, setProducts] = useState<Product[]>([]);
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 10 });
  const [total, setTotal] = useState(0);

  // Fetch data from server
  useEffect(() => {
    async function fetchProducts() {
      const res = await fetch(`/api/products?page=${pagination.pageIndex + 1}&limit=${pagination.pageSize}`);
      const data = await res.json();
      setProducts(data.products);
      setTotal(data.pagination.total);
    }
    fetchProducts();
  }, [pagination]);

  return (
    <div className="container mx-auto py-10">
      <DataTable
        columns={columns}
        data={products}
        pageCount={Math.ceil(total / pagination.pageSize)}
        pageIndex={pagination.pageIndex}
        pageSize={pagination.pageSize}
        total={total}
        onPaginationChange={(pageIndex, pageSize) => setPagination({ pageIndex, pageSize })}
        enableSelection
      />
    </div>
  );
}
```

---

## 4. File Upload Validation

### 4.1 File Upload Handler (`src/lib/upload.ts`)

```typescript
// src/lib/upload.ts
import { writeFile, mkdir } from 'fs/promises';
import path from 'path';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_DOCUMENT_TYPES = ['application/pdf'];

export interface UploadResult {
  url: string;
  filename: string;
  size: number;
  mimeType: string;
}

export async function validateAndUpload(
  file: File,
  folder: 'images' | 'files' | 'products' | 'articles',
  options: {
    maxSize?: number;
    allowedTypes?: string[];
  } = {}
): Promise<UploadResult> {
  const maxSize = options.maxSize || MAX_FILE_SIZE;
  const allowedTypes = options.allowedTypes || ALLOWED_IMAGE_TYPES;

  // Validate file size
  if (file.size > maxSize) {
    throw new Error(`File size exceeds ${maxSize / 1024 / 1024}MB limit`);
  }

  // Validate file type
  if (!allowedTypes.includes(file.type)) {
    throw new Error(`File type ${file.type} is not allowed`);
  }

  // Generate unique filename
  const ext = path.extname(file.name);
  const baseName = path.basename(file.name, ext);
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  const filename = `${baseName}-${timestamp}-${randomSuffix}${ext}`;

  // Create upload directory if not exists
  const uploadDir = path.join(process.cwd(), 'public', 'uploads', folder);
  await mkdir(uploadDir, { recursive: true });

  // Save file
  const buffer = Buffer.from(await file.arrayBuffer());
  const filePath = path.join(uploadDir, filename);
  await writeFile(filePath, buffer);

  return {
    url: `/uploads/${folder}/${filename}`,
    filename,
    size: file.size,
    mimeType: file.type,
  };
}

export function validateImage(file: File): void {
  if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    throw new Error('Only image files (JPEG, PNG, GIF, WebP) are allowed');
  }
  if (file.size > MAX_FILE_SIZE) {
    throw new Error('Image size must be less than 10MB');
  }
}
```

### 4.2 File Upload Component (`src/components/shared/FileUpload.tsx`)

```typescript
// src/components/shared/FileUpload.tsx
'use client';

import { useState, useCallback } from 'react';
import { Upload, X, File, Image as ImageIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { validateImage } from '@/lib/upload';

interface FileUploadProps {
  value?: string[];
  onChange: (urls: string[]) => void;
  maxFiles?: number;
  accept?: string;
  maxSize?: number;
}

export function FileUpload({
  value = [],
  onChange,
  maxFiles = 5,
  accept = 'image/*',
  maxSize = 10 * 1024 * 1024,
}: FileUploadProps) {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = useCallback(
    async (files: FileList) => {
      setError(null);
      
      if (value.length + files.length > maxFiles) {
        setError(`Maximum ${maxFiles} files allowed`);
        return;
      }

      setUploading(true);

      try {
        const uploadedUrls: string[] = [];

        for (const file of Array.from(files)) {
          // Validate
          if (file.size > maxSize) {
            throw new Error(`${file.name} exceeds ${maxSize / 1024 / 1024}MB`);
          }

          const formData = new FormData();
          formData.append('file', file);

          const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData,
          });

          if (!res.ok) {
            throw new Error('Upload failed');
          }

          const data = await res.json();
          uploadedUrls.push(data.url);
        }

        onChange([...value, ...uploadedUrls]);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setUploading(false);
      }
    },
    [value, maxFiles, maxSize, onChange]
  );

  const removeFile = (index: number) => {
    const newValue = [...value];
    newValue.splice(index, 1);
    onChange(newValue);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
        {value.map((url, index) => (
          <div key={index} className="relative group aspect-square rounded-lg overflow-hidden border">
            <img src={url} alt={`Upload ${index + 1}`} className="w-full h-full object-cover" />
            <Button
              type="button"
              variant="destructive"
              size="icon"
              className="absolute top-2 right-2 h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
              onClick={() => removeFile(index)}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        ))}

        {value.length < maxFiles && (
          <label className="flex flex-col items-center justify-center aspect-square rounded-lg border-2 border-dashed hover:bg-muted/50 cursor-pointer transition-colors">
            <Upload className="h-8 w-8 text-muted-foreground" />
            <span className="mt-2 text-sm text-muted-foreground">Upload</span>
            <input
              type="file"
              className="hidden"
              accept={accept}
              multiple={value.length < maxFiles - 1}
              onChange={(e) => e.target.files && handleUpload(e.target.files)}
              disabled={uploading}
            />
          </label>
        )}
      </div>

      {error && <p className="text-sm text-red-500">{error}</p>}
    </div>
  );
}
```

---

*Document Version: 1.0*
*Last Updated: 2026-02-27*
