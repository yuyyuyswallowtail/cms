// prisma/seed.ts
import { PrismaClient, RoleType, UserStatus, ProductStatus, ArticleStatus } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Create roles
  const roles = [
    { name: RoleType.SUPERADMIN, description: 'Super Administrator', isDefault: false },
    { name: RoleType.ADMIN, description: 'Administrator', isDefault: false },
    { name: RoleType.MANAGER, description: 'Manager', isDefault: false },
    { name: RoleType.STAFF, description: 'Staff', isDefault: false },
    { name: RoleType.CUSTOMER, description: 'Customer', isDefault: true },
    { name: RoleType.GUEST, description: 'Guest', isDefault: false },
  ];

  for (const role of roles) {
    await prisma.role.upsert({
      where: { name: role.name },
      update: {},
      create: role,
    });
  }
  console.log('✅ Roles created');

  // Create superadmin user
  const hashedPassword = await bcrypt.hash('Admin123!', 12);
  const superadmin = await prisma.user.upsert({
    where: { email: 'admin@cms.com' },
    update: {},
    create: {
      email: 'admin@cms.com',
      name: 'Super Admin',
      password: hashedPassword,
      status: UserStatus.ACTIVE,
      emailVerified: true,
      verifiedAt: new Date(),
    },
  });

  // Assign superadmin role
  const superadminRole = await prisma.role.findUnique({ where: { name: RoleType.SUPERADMIN } });
  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: superadmin.id,
        roleId: superadminRole!.id,
      },
    },
    update: {},
    create: {
      userId: superadmin.id,
      roleId: superadminRole!.id,
    },
  });

  // Create permissions for superadmin
  const allPermissions = [
    { name: 'users.read', resource: 'users', action: 'read' },
    { name: 'users.write', resource: 'users', action: 'write' },
    { name: 'users.update', resource: 'users', action: 'update' },
    { name: 'users.delete', resource: 'users', action: 'delete' },
    { name: 'roles.read', resource: 'roles', action: 'read' },
    { name: 'roles.write', resource: 'roles', action: 'write' },
    { name: 'products.read', resource: 'products', action: 'read' },
    { name: 'products.write', resource: 'products', action: 'write' },
    { name: 'products.update', resource: 'products', action: 'update' },
    { name: 'products.delete', resource: 'products', action: 'delete' },
    { name: 'orders.read', resource: 'orders', action: 'read' },
    { name: 'orders.write', resource: 'orders', action: 'write' },
    { name: 'orders.update', resource: 'orders', action: 'update' },
    { name: 'articles.read', resource: 'articles', action: 'read' },
    { name: 'articles.write', resource: 'articles', action: 'write' },
    { name: 'articles.update', resource: 'articles', action: 'update' },
    { name: 'articles.delete', resource: 'articles', action: 'delete' },
    { name: 'payments.read', resource: 'payments', action: 'read' },
    { name: 'payments.update', resource: 'payments', action: 'update' },
    { name: 'reports.read', resource: 'reports', action: 'read' },
    { name: 'settings.read', resource: 'settings', action: 'read' },
    { name: 'settings.write', resource: 'settings', action: 'write' },
  ];

  for (const perm of allPermissions) {
    await prisma.permission.upsert({
      where: {
        roleId_name: {
          roleId: superadminRole!.id,
          name: perm.name,
        },
      },
      update: {},
      create: {
        ...perm,
        roleId: superadminRole!.id,
      },
    });
  }
  console.log('✅ Superadmin created (admin@cms.com / Admin123!)');

  // Create default customer role permissions
  const customerRole = await prisma.role.findUnique({ where: { name: RoleType.CUSTOMER } });
  const customerPermissions = [
    { name: 'products.read', resource: 'products', action: 'read' },
    { name: 'orders.read', resource: 'orders', action: 'read' },
    { name: 'orders.write', resource: 'orders', action: 'write' },
    { name: 'articles.read', resource: 'articles', action: 'read' },
  ];

  for (const perm of customerPermissions) {
    await prisma.permission.upsert({
      where: {
        roleId_name: {
          roleId: customerRole!.id,
          name: perm.name,
        },
      },
      update: {},
      create: {
        ...perm,
        roleId: customerRole!.id,
      },
    });
  }
  console.log('✅ Customer permissions created');

  // Create company profile
  await prisma.companyProfile.upsert({
    where: { slug: 'default' },
    update: {},
    create: {
      name: 'Your Company Name',
      slug: 'default',
      description: 'Your company description here',
      email: 'contact@yourcompany.com',
      phone: '+62 123 4567 890',
      address: 'Jl. Example No. 123',
      city: 'Jakarta',
      province: 'DKI Jakarta',
      country: 'Indonesia',
    },
  });
  console.log('✅ Company profile created');

  // Create product categories
  const categories = [
    { name: 'Electronics', slug: 'electronics', description: 'Electronic devices and accessories' },
    { name: 'Clothing', slug: 'clothing', description: 'Fashion and apparel' },
    { name: 'Home & Garden', slug: 'home-garden', description: 'Home improvement and gardening' },
  ];

  for (const cat of categories) {
    await prisma.productCategory.upsert({
      where: { slug: cat.slug },
      update: {},
      create: cat,
    });
  }
  console.log('✅ Categories created');

  // Create sample products
  const electronics = await prisma.productCategory.findUnique({ where: { slug: 'electronics' } });
  
  await prisma.product.upsert({
    where: { slug: 'sample-laptop' },
    update: {},
    create: {
      name: 'Professional Laptop',
      slug: 'sample-laptop',
      description: 'High-performance laptop for professionals',
      price: 15000000,
      costPrice: 10000000,
      stock: 50,
      sku: 'LAPTOP-001',
      status: ProductStatus.PUBLISHED,
      featured: true,
      categoryId: electronics?.id,
    },
  });
  console.log('✅ Sample products created');

  // Create sample article
  await prisma.article.upsert({
    where: { slug: 'welcome-to-our-company' },
    update: {},
    create: {
      title: 'Welcome to Our Company',
      slug: 'welcome-to-our-company',
      content: '# Welcome\n\nThis is a sample article demonstrating markdown support.\n\n## Features\n\n- Rich text formatting\n- Code blocks\n- Images and more!',
      excerpt: 'Welcome to our company website',
      status: ArticleStatus.PUBLISHED,
      publishedAt: new Date(),
      author: 'Admin',
    },
  });
  console.log('✅ Sample article created');

  console.log('🎉 Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
