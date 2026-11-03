import { createHash, createHmac, randomBytes } from 'node:crypto';
/** 256-bit opaque session token, base64url. */
export const newSessionToken = (): string => randomBytes(32).toString('base64url');
export const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');
export const hmacHex = (key: string, value: string): string => createHmac('sha256', key).update(value, 'utf8').digest('hex');
export const isSessionTokenShape = (value: string): boolean => /^[A-Za-z0-9_-]{43}$/.test(value);
