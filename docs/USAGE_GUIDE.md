# Usage Guide

## Overview

This comprehensive usage guide provides practical examples, integration patterns, and real-world scenarios for implementing the NestJS AWS Cognito authentication system in your applications.

## Table of Contents

- [Quick Start](#quick-start)
- [Frontend Integration](#frontend-integration)
- [Advanced Authentication Flows](#advanced-authentication-flows)
- [Security Implementation](#security-implementation)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Quick Start

### 1. Environment Setup

Create a `.env` file in your project root:

```bash
# AWS Cognito Configuration
AWS_COGNITO_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
AWS_COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Application Configuration
PORT=3000
NODE_ENV=development
```

### 2. Basic Integration

#### Install Dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/config @nestjs/passport
npm install @aws-sdk/client-cognito-identity-provider passport-jwt jwks-rsa
npm install --save-dev @types/passport-jwt
```

#### Simple Authentication Example

```typescript
// app.controller.ts
import { Controller, Post, Body, UseGuards, Get, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth/auth.service';

@Controller()
export class AppController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() loginData: { email: string; password: string }) {
    return await this.authService.login(loginData);
  }

  @Post('register')
  async register(@Body() registerData: any) {
    return await this.authService.signup(registerData);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req) {
    return {
      message: 'Authenticated successfully',
      user: req.user,
    };
  }
}
```

### 3. Testing the API

#### User Registration

```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "name": "John Doe"
  }'
```

#### User Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Protected Route Access

```bash
curl -X GET http://localhost:3000/auth/get-user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "access_token": "YOUR_ACCESS_TOKEN"
  }'
```

## Frontend Integration

### React Integration

#### Authentication Context

```typescript
// AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';

interface AuthContextType {
  user: any;
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  signup: (userData: any) => Promise<boolean>;
  isAuthenticated: boolean;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        const result = await response.json();
        const token = result.AuthenticationResult.AccessToken;
        
        localStorage.setItem('accessToken', token);
        setUser({ email, token });
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const signup = async (userData: any): Promise<boolean> => {
    try {
      const response = await fetch('/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData),
      });

      return response.ok;
    } catch (error) {
      console.error('Signup failed:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('accessToken');
    setUser(null);
  };

  useEffect(() => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      // Verify token validity
      fetch('/auth/get-user', {
        method: 'GET',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ access_token: token }),
      })
      .then(response => {
        if (response.ok) {
          return response.json();
        }
        throw new Error('Token invalid');
      })
      .then(userData => {
        setUser({ ...userData, token });
      })
      .catch(() => {
        localStorage.removeItem('accessToken');
      })
      .finally(() => {
        setLoading(false);
      });
    } else {
      setLoading(false);
    }
  }, []);

  return (
    <AuthContext.Provider value={{
      user,
      login,
      logout,
      signup,
      isAuthenticated: !!user,
      loading,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

#### Login Component

```typescript
// LoginForm.tsx
import React, { useState } from 'react';
import { useAuth } from './AuthContext';

export const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const success = await login(email, password);
    if (!success) {
      setError('Invalid credentials');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>
      <div>
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      {error && <div style={{ color: 'red' }}>{error}</div>}
      <button type="submit">Login</button>
    </form>
  );
};
```

#### Protected Route Component

```typescript
// ProtectedRoute.tsx
import React from 'react';
import { useAuth } from './AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <div>Please log in to access this page</div>;
  }

  return <>{children}</>;
};
```

### Angular Integration

#### Authentication Service

```typescript
// auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

interface User {
  email: string;
  token: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject: BehaviorSubject<User | null>;
  public currentUser: Observable<User | null>;

  constructor(private http: HttpClient) {
    this.currentUserSubject = new BehaviorSubject<User | null>(
      JSON.parse(localStorage.getItem('currentUser') || 'null')
    );
    this.currentUser = this.currentUserSubject.asObservable();
  }

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  login(email: string, password: string) {
    return this.http.post<any>('/auth/login', { email, password })
      .pipe(map(response => {
        if (response && response.AuthenticationResult) {
          const user = {
            email,
            token: response.AuthenticationResult.AccessToken
          };
          localStorage.setItem('currentUser', JSON.stringify(user));
          this.currentUserSubject.next(user);
        }
        return response;
      }));
  }

  signup(userData: any) {
    return this.http.post('/auth/signup', userData);
  }

  logout() {
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
  }
}
```

#### Authentication Guard

```typescript
// auth.guard.ts
import { Injectable } from '@angular/core';
import { Router, CanActivate } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private router: Router,
    private authService: AuthService
  ) {}

  canActivate() {
    const currentUser = this.authService.currentUserValue;
    if (currentUser) {
      return true;
    }

    this.router.navigate(['/login']);
    return false;
  }
}
```

## Advanced Authentication Flows

### Multi-Factor Authentication (MFA)

```typescript
// mfa.service.ts
import { Injectable } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class MfaService {
  constructor(private readonly authService: AuthService) {}

  async enableMfa(userId: string, phoneNumber: string) {
    // Implementation for enabling MFA
    // This would involve AWS Cognito MFA setup
  }

  async verifyMfaToken(session: string, mfaCode: string) {
    // Implementation for MFA verification
    // This would use RespondToAuthChallengeCommand with SMS_MFA
  }
}
```

### Social Login Integration

```typescript
// social-auth.service.ts
import { Injectable } from '@nestjs/common';

@Injectable()
export class SocialAuthService {
  async googleLogin(googleToken: string) {
    // Implementation for Google OAuth integration
    // This would involve verifying Google token and creating/linking Cognito user
  }

  async facebookLogin(facebookToken: string) {
    // Implementation for Facebook OAuth integration
  }
}
```

### Refresh Token Management

```typescript
// token.service.ts
import { Injectable } from '@nestjs/common';
import { CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider';

@Injectable()
export class TokenService {
  private readonly client: CognitoIdentityProviderClient;

  constructor() {
    this.client = new CognitoIdentityProviderClient({
      region: process.env.AWS_COGNITO_REGION,
    });
  }

  async refreshToken(refreshToken: string, username: string) {
    const command = new InitiateAuthCommand({
      ClientId: process.env.AWS_COGNITO_CLIENT_ID,
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        SECRET_HASH: this.generateSecretHash(username),
      },
    });

    try {
      const response = await this.client.send(command);
      return response.AuthenticationResult;
    } catch (error) {
      throw new Error('Failed to refresh token');
    }
  }

  private generateSecretHash(username: string): string {
    // Implementation same as in AuthService
  }
}
```

## Security Implementation

### Rate Limiting

```typescript
// rate-limiting.module.ts
import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60, // Time window in seconds
      limit: 10, // Maximum requests per ttl
    }),
  ],
})
export class SecurityModule {}
```

```typescript
// auth.controller.ts (with rate limiting)
import { UseGuards } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  // ... controller methods
}
```

### Input Validation

```typescript
// validation.pipe.ts
import { PipeTransform, Injectable, ArgumentMetadata, BadRequestException } from '@nestjs/common';
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    
    const object = plainToClass(metatype, value);
    const errors = await validate(object);
    
    if (errors.length > 0) {
      const errorMessages = errors.map(error => 
        Object.values(error.constraints || {}).join(', ')
      ).join('; ');
      
      throw new BadRequestException(`Validation failed: ${errorMessages}`);
    }
    
    return value;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
```

### Security Headers

```typescript
// security.middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class SecurityMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Security headers
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.header('Content-Security-Policy', "default-src 'self'");
    
    next();
  }
}
```

## Production Deployment

### Docker Configuration

```dockerfile
# Dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000

USER node

CMD ["npm", "run", "start:prod"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - AWS_COGNITO_REGION=${AWS_COGNITO_REGION}
      - AWS_COGNITO_USER_POOL_ID=${AWS_COGNITO_USER_POOL_ID}
      - AWS_COGNITO_CLIENT_ID=${AWS_COGNITO_CLIENT_ID}
      - AWS_COGNITO_CLIENT_SECRET=${AWS_COGNITO_CLIENT_SECRET}
    restart: unless-stopped
```

### AWS Lambda Deployment

```typescript
// lambda.ts
import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { Context, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { AppModule } from './app.module';
import * as express from 'express';

let cachedServer: any;

async function bootstrap() {
  if (!cachedServer) {
    const expressApp = express();
    const app = await NestFactory.create(AppModule, new ExpressAdapter(expressApp));
    app.enableCors();
    await app.init();
    cachedServer = expressApp;
  }
  return cachedServer;
}

export const handler = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  const server = await bootstrap();
  return new Promise((resolve, reject) => {
    const callback = (error: any, response: APIGatewayProxyResult) => {
      if (error) reject(error);
      else resolve(response);
    };
    
    // Process the event
    server(event, context, callback);
  });
};
```

### Environment-Specific Configuration

```typescript
// config/configuration.ts
export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  aws: {
    region: process.env.AWS_COGNITO_REGION,
    userPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
    clientId: process.env.AWS_COGNITO_CLIENT_ID,
    clientSecret: process.env.AWS_COGNITO_CLIENT_SECRET,
  },
  jwt: {
    expiresIn: process.env.JWT_EXPIRES_IN || '3600s',
  },
  cors: {
    origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
    credentials: true,
  },
});
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "NotAuthorizedException" Error

**Problem**: User receives "NotAuthorizedException" when trying to authenticate.

**Solutions**:
```typescript
// Check SECRET_HASH generation
private cognitoSecretHash(username: string): string {
  const secret = process.env.AWS_COGNITO_CLIENT_SECRET;
  if (!secret) {
    throw new Error('AWS_COGNITO_CLIENT_SECRET is not configured');
  }
  
  const message = username + this.clientId;
  return crypto.createHmac('sha256', secret).update(message).digest('base64');
}
```

#### 2. CORS Issues

**Problem**: Frontend cannot access the API due to CORS restrictions.

**Solution**:
```typescript
// main.ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.enableCors({
    origin: [
      'http://localhost:3000',
      'https://yourdomain.com',
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
  
  await app.listen(3000);
}
```

#### 3. JWT Validation Errors

**Problem**: JWT tokens are not being validated correctly.

**Solution**:
```typescript
// jwt.strategy.ts - Debug JWKS configuration
constructor(
  private readonly authService: AuthService,
  private configService: ConfigService,
) {
  const jwksUri = `${configService.get<string>('authority')}/.well-known/jwks.json`;
  console.log('JWKS URI:', jwksUri); // Debug output
  
  super({
    secretOrKeyProvider: passportJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri,
    }),
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    audience: configService.get<string>('clientId'),
    issuer: configService.get<string>('authority'),
    algorithms: ['RS256'],
  });
}
```

### Debug Logging

```typescript
// logger.service.ts
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CustomLogger extends Logger {
  logAuthAttempt(email: string, success: boolean) {
    const message = `Authentication attempt for ${email}: ${success ? 'SUCCESS' : 'FAILED'}`;
    if (success) {
      this.log(message);
    } else {
      this.warn(message);
    }
  }
  
  logCognitoError(error: any, operation: string) {
    this.error(`Cognito ${operation} error: ${error.name} - ${error.message}`);
  }
}
```

## Best Practices

### 1. Secure Configuration Management

```typescript
// Use AWS Secrets Manager for production
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

export class ConfigService {
  private secrets: any = {};

  async loadSecrets() {
    if (process.env.NODE_ENV === 'production') {
      const client = new SecretsManagerClient({ region: 'us-east-1' });
      const command = new GetSecretValueCommand({
        SecretId: 'prod/nestjs-cognito/secrets',
      });
      
      const response = await client.send(command);
      this.secrets = JSON.parse(response.SecretString || '{}');
    }
  }

  get(key: string): string {
    return this.secrets[key] || process.env[key];
  }
}
```

### 2. Graceful Error Handling

```typescript
// error-handler.interceptor.ts
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable()
export class ErrorHandlerInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError(error => {
        // Log error for monitoring
        console.error('Unhandled error:', error);
        
        // Transform error for client
        const response = {
          statusCode: 500,
          message: 'An unexpected error occurred',
          timestamp: new Date().toISOString(),
        };
        
        return throwError(() => response);
      }),
    );
  }
}
```

### 3. Health Checks

```typescript
// health.controller.ts
import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
    };
  }

  @Get('cognito')
  async checkCognito() {
    try {
      // Simple Cognito connectivity check
      // You could ping Cognito service here
      return {
        status: 'ok',
        service: 'cognito',
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        status: 'error',
        service: 'cognito',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }
}
```

### 4. Performance Monitoring

```typescript
// performance.interceptor.ts
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class PerformanceInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const start = Date.now();
    
    return next.handle().pipe(
      tap(() => {
        const duration = Date.now() - start;
        const request = context.switchToHttp().getRequest();
        
        console.log(`${request.method} ${request.url} - ${duration}ms`);
        
        // Send metrics to monitoring service
        if (duration > 1000) {
          console.warn(`Slow request detected: ${request.url} took ${duration}ms`);
        }
      }),
    );
  }
}
```

---

*This usage guide provides comprehensive examples and patterns for implementing the NestJS AWS Cognito authentication system in real-world applications. Follow these patterns to build secure, scalable authentication solutions.*