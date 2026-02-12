/**
 * Authentication Module - Production-grade auth with password hashing
 */

import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
  lastLoginAt: Date | null;
}

export interface AuthResult {
  success: boolean;
  user?: User;
  token?: string;
  error?: AuthError;
}

export type AuthError = 
  | 'USER_NOT_FOUND'
  | 'INVALID_PASSWORD'
  | 'EMAIL_EXISTS'
  | 'INVALID_EMAIL_FORMAT'
  | 'PASSWORD_TOO_WEAK';

export interface AuthConfig {
  saltRounds: number;
  tokenSecret: string;
  tokenExpiryMs: number;
}

export class AuthService {
  private users: Map<string, User> = new Map();
  private emailIndex: Map<string, string> = new Map();

  constructor(private config: AuthConfig) {
    if (!config.tokenSecret) {
      throw new Error('AUTH_CONFIG_INVALID: tokenSecret is required');
    }
  }

  async register(email: string, password: string): Promise<AuthResult> {
    if (!this.isValidEmail(email)) {
      return { success: false, error: 'INVALID_EMAIL_FORMAT' };
    }

    if (!this.isStrongPassword(password)) {
      return { success: false, error: 'PASSWORD_TOO_WEAK' };
    }

    if (this.emailIndex.has(email.toLowerCase())) {
      return { success: false, error: 'EMAIL_EXISTS' };
    }

    const passwordHash = await bcrypt.hash(password, this.config.saltRounds);
    const user: User = {
      id: uuidv4(),
      email: email.toLowerCase(),
      passwordHash,
      createdAt: new Date(),
      lastLoginAt: null,
    };

    this.users.set(user.id, user);
    this.emailIndex.set(user.email, user.id);

    const token = this.generateToken(user);
    return { success: true, user, token };
  }

  async login(email: string, password: string): Promise<AuthResult> {
    const userId = this.emailIndex.get(email.toLowerCase());
    if (!userId) {
      return { success: false, error: 'USER_NOT_FOUND' };
    }

    const user = this.users.get(userId);
    if (!user) {
      return { success: false, error: 'USER_NOT_FOUND' };
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return { success: false, error: 'INVALID_PASSWORD' };
    }

    user.lastLoginAt = new Date();
    const token = this.generateToken(user);
    return { success: true, user, token };
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<AuthResult> {
    const user = this.users.get(userId);
    if (!user) {
      return { success: false, error: 'USER_NOT_FOUND' };
    }

    const valid = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!valid) {
      return { success: false, error: 'INVALID_PASSWORD' };
    }

    if (!this.isStrongPassword(newPassword)) {
      return { success: false, error: 'PASSWORD_TOO_WEAK' };
    }

    user.passwordHash = await bcrypt.hash(newPassword, this.config.saltRounds);
    return { success: true, user };
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private isStrongPassword(password: string): boolean {
    return password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password);
  }

  private generateToken(user: User): string {
    const payload = { userId: user.id, email: user.email, exp: Date.now() + this.config.tokenExpiryMs };
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }
}
