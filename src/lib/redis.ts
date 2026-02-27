import { createClient, RedisClientType } from 'redis';

let redisClient: RedisClientType | null = null;

export async function getRedisClient(): Promise<RedisClientType> {
  if (redisClient && redisClient.isOpen) {
    return redisClient;
  }

  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  
  redisClient = createClient({
    url,
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) {
          return new Error('Redis reconnection failed');
        }
        return Math.min(retries * 100, 3000);
      },
    },
  });

  redisClient.on('error', (err) => {
    console.error('Redis Client Error:', err);
  });

  await redisClient.connect();
  return redisClient;
}

// Utility functions
export const redis = {
  async get(key: string): Promise<string | null> {
    const client = await getRedisClient();
    return client.get(key);
  },

  async set(key: string, value: string, ttl?: number): Promise<void> {
    const client = await getRedisClient();
    if (ttl) {
      await client.setEx(key, ttl, value);
    } else {
      await client.set(key, value);
    }
  },

  async del(...keys: string[]): Promise<void> {
    const client = await getRedisClient();
    await client.del(...keys);
  },

  async incr(key: string): Promise<number> {
    const client = await getRedisClient();
    return client.incr(key);
  },

  async expire(key: string, ttl: number): Promise<void> {
    const client = await getRedisClient();
    await client.expire(key, ttl);
  },

  async keys(pattern: string): Promise<string[]> {
    const client = await getRedisClient();
    return client.keys(pattern);
  },

  async zadd(key: string, score: number, member: string): Promise<void> {
    const client = await getRedisClient();
    await client.zAdd(key, { score, value: member });
  },

  async zrangebyscore(key: string, min: number, max: number): Promise<string[]> {
    const client = await getRedisClient();
    return client.zRangeByScore(key, min, max);
  },

  async publish(channel: string, message: string): Promise<number> {
    const client = await getRedisClient();
    return client.publish(channel, message);
  },
};
