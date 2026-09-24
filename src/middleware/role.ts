import { Request, Response, NextFunction } from 'express';
import { Role } from '../types';

// Usage: requireRole('admin') or requireRole('admin', 'analyst')
export function requireRole(...allowedRoles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission for this action.' });
    }
    next();
  };
}
