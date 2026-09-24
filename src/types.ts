// Shared types used across ULPF's backend.

export type Role = 'pending' | 'viewer' | 'analyst' | 'admin';

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
  sensitiveAccess: boolean;
}

// Augments Express's Request with the user object requireAuth attaches.
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export interface MaskingConfig {
  email: boolean;
  password: boolean;
  apiKey: boolean;
  phone: boolean;
  ip: boolean;
  [key: string]: boolean;
}

export interface NormalizedEvent {
  eventId?: string;
  timestamp: string;
  sourceIP: string | null;
  destIP: string | null;
  action: string | null;
  protocol: string | null;
  vendor: string;
  eventType: string;
  sourceType: string;
  detectedFormat?: string;
  [key: string]: any;
}

export interface ParsedFields {
  vendor?: string | null;
  eventType?: string | null;
  timestamp?: string | null;
  sourceIP?: string | null;
  destIP?: string | null;
  action?: string | null;
  protocol?: string | null;
  [key: string]: any;
}

// Every category of item that can be soft-deleted into the Recycle Bin.
export type RecycleCategory = 'logs' | 'accounts' | 'alerts' | 'sources';

export {};
