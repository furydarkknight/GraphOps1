import path from 'node:path'
import { defineConfig } from 'prisma/config'

export default defineConfig({
  earlyAccess: true,
  schema: path.join(import.meta.dirname, 'prisma/schema.prisma'),
  datasource: {
    url: process.env.DATABASE_URL ?? 'postgresql://graphops:graphops@127.0.0.1:5432/graphops?schema=public',
  },
  migrate: {
    adapter: async () => {
      const { PrismaPg } = await import('@prisma/adapter-pg')
      const { default: pg } = await import('pg')
      const pool = new pg.Pool({
        connectionString: process.env.DATABASE_URL ?? 'postgresql://graphops:graphops@127.0.0.1:5432/graphops?schema=public',
      })
      return new PrismaPg(pool)
    },
  },
})
