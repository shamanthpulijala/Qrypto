import { PrismaConfig } from '@prisma/config';
import { config } from './src/config';

export default {
  schema: {
    kind: 'single',
    filePath: 'prisma/schema.prisma'
  },
  studio: {
    port: 5555
  },
  earlyAccess: true
} satisfies PrismaConfig;
