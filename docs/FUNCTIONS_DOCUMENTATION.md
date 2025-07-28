# Functions Documentation

## Overview

This document provides detailed documentation for all utility functions, helper methods, and implementation-specific functions in the NestJS AWS Cognito authentication system.

## Table of Contents

- [Core Authentication Functions](#core-authentication-functions)
- [Utility Functions](#utility-functions)
- [Helper Functions](#helper-functions)
- [Validation Functions](#validation-functions)
- [Configuration Functions](#configuration-functions)
- [Error Handling Functions](#error-handling-functions)
- [Testing Utilities](#testing-utilities)

## Core Authentication Functions

### AWS Cognito Integration Functions

#### `login(user: AuthenticateRequestDto): Promise<any>`

**Location**: `src/auth/auth.service.ts`

Authenticates a user with AWS Cognito using the InitiateAuth command.

**Parameters:**
- `user`: AuthenticateRequestDto - Contains email and password

**Returns:** 
- Promise resolving to AWS Cognito authentication response

**Implementation:**
```typescript
async login(user: AuthenticateRequestDto) {
  try {
    const secretHash = this.cognitoSecretHash(user.email);
    
    const command = new InitiateAuthCommand({
      ClientId: this.clientId,
      AuthFlow: 'USER_PASSWORD_AUTH',
      AuthParameters: {
        USERNAME: user.email,
        PASSWORD: user.password,
        SECRET_HASH: secretHash,
      },
    });

    const response = await this.client.send(command);
    return response;
  } catch (error) {
    if (error.name !== '') {
      return error.name;
    }
    throw error;
  }
}
```

**Usage Example:**
```typescript
const user = { email: 'user@example.com', password: 'password123' };
const result = await authService.login(user);
console.log(result.AuthenticationResult.AccessToken);
```

**Error Handling:**
- Returns error name for known AWS Cognito errors
- Throws original error for unknown exceptions

---

#### `signup(signupRequest: SignupRequestDto, attributes?: Record<string, string>): Promise<string>`

**Location**: `src/auth/auth.service.ts`

Registers a new user with AWS Cognito.

**Parameters:**
- `signupRequest`: SignupRequestDto - User registration data
- `attributes`: Record<string, string> (optional) - Additional user attributes

**Returns:** 
- Promise resolving to user confirmation status string

**Implementation:**
```typescript
async signup(signupRequest: SignupRequestDto, attributes: Record<string, string> = {}) {
  attributes.email = signupRequest.email;
  const formattedAttributes = this.formatAttributes(attributes);

  const params = {
    ClientId: this.clientId,
    Username: signupRequest.email,
    Password: signupRequest.password,
    SecretHash: this.cognitoSecretHash(signupRequest.email),
    UserAttributes: formattedAttributes,
  };

  try {
    const command = new SignUpCommand(params);
    const response = await this.client.send(command);
    
    await this.setUserAttributes(signupRequest.email, {
      email_verified: 'true',
    });

    return 'UserConfirmed: ' + response.UserConfirmed || false;
  } catch (error) {
    if (error.name !== '') {
      return error.name;
    }
    throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
```

**Usage Example:**
```typescript
const signupData = {
  email: 'newuser@example.com',
  password: 'SecurePass123!',
  name: 'John Doe',
  phone_number: '+1234567890'
};

const result = await authService.signup(signupData);
console.log(result); // "UserConfirmed: true"
```

---

#### `confirmSignup(confirmSignup: ConfirmSignupRequestDto): Promise<boolean>`

**Location**: `src/auth/auth.service.ts`

Confirms user registration using a verification code.

**Parameters:**
- `confirmSignup`: ConfirmSignupRequestDto - Email and verification code

**Returns:** 
- Promise resolving to boolean confirmation status

**Implementation:**
```typescript
async confirmSignup(confirmSignup: ConfirmSignupRequestDto) {
  const params = {
    ClientId: this.clientId,
    Username: confirmSignup.email,
    ConfirmationCode: confirmSignup.code,
    SecretHash: this.cognitoSecretHash(confirmSignup.email),
  };

  try {
    const command = new ConfirmSignUpCommand(params);
    await this.client.send(command);
    return true;
  } catch (error) {
    if (error.name !== '') {
      return error.name;
    }
    throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
```

**Usage Example:**
```typescript
const confirmData = {
  email: 'user@example.com',
  code: '123456'
};

const confirmed = await authService.confirmSignup(confirmData);
if (confirmed === true) {
  console.log('User confirmed successfully');
}
```

---

#### `forgotPassword(email: string): Promise<string>`

**Location**: `src/auth/auth.service.ts`

Initiates the password reset process for a user.

**Parameters:**
- `email`: string - User's email address

**Returns:** 
- Promise resolving to status message

**Implementation:**
```typescript
async forgotPassword(email: string): Promise<string> {
  const params = {
    ClientId: this.clientId,
    SecretHash: this.cognitoSecretHash(email),
    Username: email,
  };

  try {
    const command = new ForgotPasswordCommand(params);
    await this.client.send(command);
    return 'Reset code has been sent';
  } catch (error) {
    if (error.name !== '') {
      return error.name;
    }
    throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
```

**Usage Example:**
```typescript
const result = await authService.forgotPassword('user@example.com');
console.log(result); // "Reset code has been sent"
```

---

## Utility Functions

### `formatAttributes(attributes: Record<string, string>): Array<{ Name: string; Value: string }>`

**Location**: `src/auth/auth.service.ts` (private method)

Converts a key-value object to AWS Cognito attribute format.

**Parameters:**
- `attributes`: Record<string, string> - Key-value pairs of user attributes

**Returns:** 
- Array of objects with Name and Value properties

**Implementation:**
```typescript
private formatAttributes(attributes: Record<string, string>): Array<{ Name: string; Value: string }> {
  return Object.entries(attributes).map(([key, value]) => ({
    Name: key,
    Value: value,
  }));
}
```

**Usage Example:**
```typescript
const attributes = {
  name: 'John Doe',
  email: 'john@example.com',
  phone_number: '+1234567890'
};

const formatted = this.formatAttributes(attributes);
// Result: [
//   { Name: 'name', Value: 'John Doe' },
//   { Name: 'email', Value: 'john@example.com' },
//   { Name: 'phone_number', Value: '+1234567890' }
// ]
```

---

### `cognitoSecretHash(username: string): string`

**Location**: `src/auth/auth.service.ts` (private method)

Generates a SECRET_HASH for AWS Cognito authentication.

**Parameters:**
- `username`: string - Username (typically email) for hash generation

**Returns:** 
- Base64-encoded HMAC-SHA256 hash string

**Implementation:**
```typescript
private cognitoSecretHash(username: string): string {
  const secret = process.env.AWS_COGNITO_CLIENT_SECRET;
  const message = username + this.clientId;
  
  return crypto.createHmac('sha256', secret).update(message).digest('base64');
}
```

**Usage Example:**
```typescript
const hash = this.cognitoSecretHash('user@example.com');
console.log(hash); // "K7MDENG/bPxRfiCYEXAMPLEKEY=="
```

**Security Notes:**
- Uses HMAC-SHA256 for cryptographic hashing
- Combines username and client ID for uniqueness
- Required for AWS Cognito operations when client secret is configured

---

## Helper Functions

### JWT Strategy Validation

#### `validate(payload: any): Promise<any>`

**Location**: `src/auth/jwt.strategy.ts`

Validates JWT payload and returns user information.

**Parameters:**
- `payload`: any - Decoded JWT payload from AWS Cognito

**Returns:** 
- Promise resolving to user payload

**Implementation:**
```typescript
public async validate(payload: any) {
  return payload;
}
```

**Usage in Guards:**
```typescript
@UseGuards(AuthGuard('jwt'))
@Get('profile')
getProfile(@Request() req) {
  return req.user; // Contains validated payload
}
```

**Payload Structure:**
```typescript
// Typical AWS Cognito JWT payload
{
  sub: "user-uuid",
  aud: "client-id",
  iss: "https://cognito-idp.region.amazonaws.com/user-pool-id",
  token_use: "access",
  scope: "aws.cognito.signin.user.admin",
  auth_time: 1640995200,
  exp: 1640998800,
  iat: 1640995200,
  jti: "jwt-id",
  username: "user@example.com"
}
```

---

### Bootstrap Function

#### `bootstrap(): Promise<void>`

**Location**: `src/main.ts`

Application bootstrap function that initializes the NestJS application.

**Implementation:**
```typescript
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
```

**Features:**
- Creates NestJS application instance
- Configures global fetch polyfill
- Starts server on port 3000

**Extended Bootstrap Example:**
```typescript
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Enable CORS
  app.enableCors({
    origin: ['http://localhost:3000', 'https://yourdomain.com'],
    credentials: true,
  });
  
  // Global prefix
  app.setGlobalPrefix('api');
  
  // Validation pipe
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    transform: true,
  }));
  
  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  console.log(`Application is running on: ${await app.getUrl()}`);
}
```

---

## Validation Functions

### Custom Validation Decorators

#### Email Validation

```typescript
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailValidationDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}
```

#### Password Validation

```typescript
import { IsString, MinLength, Matches } from 'class-validator';

export class PasswordValidationDto {
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain uppercase, lowercase, number and special character'
  })
  password: string;
}
```

### Validation Helper Functions

#### `validateEmail(email: string): boolean`

```typescript
function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Usage
if (!validateEmail('user@example.com')) {
  throw new BadRequestException('Invalid email format');
}
```

#### `validatePassword(password: string): { valid: boolean; errors: string[] }`

```typescript
function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[@$!%*?&]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Usage
const validation = validatePassword('weak');
if (!validation.valid) {
  throw new BadRequestException(validation.errors);
}
```

---

## Configuration Functions

### Configuration Factory

#### `authConfig(): ConfigObject`

**Location**: `src/auth/auth.config.ts`

Factory function that creates configuration object for AWS Cognito.

**Implementation:**
```typescript
export default () => ({
  userPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
  clientId: process.env.AWS_COGNITO_CLIENT_ID,
  region: process.env.AWS_COGNITO_REGION,
  authority: `https://cognito-idp.${process.env.AWS_COGNITO_REGION}.amazonaws.com/${process.env.AWS_COGNITO_USER_POOL_ID}`,
});
```

**Usage in Module:**
```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [authConfig],
    }),
  ],
})
export class AppModule {}
```

#### Environment Validation Function

```typescript
function validateEnvironment(): void {
  const requiredEnvVars = [
    'AWS_COGNITO_REGION',
    'AWS_COGNITO_USER_POOL_ID',
    'AWS_COGNITO_CLIENT_ID',
    'AWS_COGNITO_CLIENT_SECRET'
  ];

  const missingVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }
}

// Usage in main.ts
validateEnvironment();
```

---

## Error Handling Functions

### Custom Exception Filters

#### `CognitoExceptionFilter`

```typescript
import { ExceptionFilter, Catch, ArgumentsHost, HttpStatus } from '@nestjs/common';
import { Response } from 'express';

@Catch()
export class CognitoExceptionFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    const errorMapping = this.mapCognitoError(exception);
    
    response.status(errorMapping.status).json({
      statusCode: errorMapping.status,
      message: errorMapping.message,
      error: errorMapping.error,
      timestamp: new Date().toISOString(),
      path: ctx.getRequest().url,
    });
  }

  private mapCognitoError(exception: any): { status: number; message: string; error: string } {
    const errorMap = {
      'UserNotConfirmedException': {
        status: HttpStatus.UNAUTHORIZED,
        message: 'User account is not confirmed. Please check your email for verification.',
        error: 'User Not Confirmed'
      },
      'NotAuthorizedException': {
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid email or password.',
        error: 'Unauthorized'
      },
      'UserNotFoundException': {
        status: HttpStatus.NOT_FOUND,
        message: 'User account not found.',
        error: 'User Not Found'
      },
      'InvalidPasswordException': {
        status: HttpStatus.BAD_REQUEST,
        message: 'Password does not meet requirements.',
        error: 'Invalid Password'
      },
      'CodeMismatchException': {
        status: HttpStatus.BAD_REQUEST,
        message: 'Invalid verification code.',
        error: 'Code Mismatch'
      },
      'ExpiredCodeException': {
        status: HttpStatus.BAD_REQUEST,
        message: 'Verification code has expired.',
        error: 'Expired Code'
      }
    };

    return errorMap[exception.name] || {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error',
      error: 'Internal Server Error'
    };
  }
}
```

#### Error Response Helper Function

```typescript
function createErrorResponse(
  error: string,
  message: string,
  statusCode: number = 400
): { statusCode: number; message: string; error: string; timestamp: string } {
  return {
    statusCode,
    message,
    error,
    timestamp: new Date().toISOString(),
  };
}

// Usage
const errorResponse = createErrorResponse(
  'Validation Error',
  'Email is required',
  400
);
```

---

## Testing Utilities

### Mock Functions

#### AWS Cognito Client Mock

```typescript
export const mockCognitoClient = {
  send: jest.fn().mockImplementation((command) => {
    if (command.constructor.name === 'InitiateAuthCommand') {
      return Promise.resolve({
        AuthenticationResult: {
          AccessToken: 'mock-access-token',
          IdToken: 'mock-id-token',
          RefreshToken: 'mock-refresh-token',
          TokenType: 'Bearer',
          ExpiresIn: 3600
        }
      });
    }
    
    if (command.constructor.name === 'SignUpCommand') {
      return Promise.resolve({
        UserConfirmed: false,
        UserSub: 'mock-user-sub'
      });
    }
    
    return Promise.resolve({});
  })
};
```

#### Service Testing Helper

```typescript
export function createTestingModule(overrides = {}) {
  return Test.createTestingModule({
    providers: [
      AuthService,
      {
        provide: ConfigService,
        useValue: {
          get: jest.fn((key: string) => {
            const config = {
              userPoolId: 'test-pool-id',
              clientId: 'test-client-id',
              region: 'us-east-1',
              authority: 'https://cognito-idp.us-east-1.amazonaws.com/test-pool-id',
              ...overrides
            };
            return config[key];
          }),
        },
      },
    ],
  }).compile();
}
```

#### Mock DTO Factory

```typescript
export const createMockAuthenticateRequest = (
  overrides: Partial<AuthenticateRequestDto> = {}
): AuthenticateRequestDto => ({
  email: 'test@example.com',
  password: 'TestPassword123!',
  ...overrides
});

export const createMockSignupRequest = (
  overrides: Partial<SignupRequestDto> = {}
): SignupRequestDto => ({
  email: 'test@example.com',
  password: 'TestPassword123!',
  name: 'Test User',
  phone_number: '+1234567890',
  gender: 'male',
  birthdate: '1990-01-01',
  address: '123 Test St',
  scope: 'email',
  ...overrides
});
```

### Test Utilities

#### Async Test Helper

```typescript
export const waitFor = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

// Usage in tests
await waitFor(1000); // Wait 1 second
```

#### Environment Setup for Tests

```typescript
export function setupTestEnvironment(): void {
  process.env.AWS_COGNITO_REGION = 'us-east-1';
  process.env.AWS_COGNITO_USER_POOL_ID = 'us-east-1_testpool';
  process.env.AWS_COGNITO_CLIENT_ID = 'test-client-id';
  process.env.AWS_COGNITO_CLIENT_SECRET = 'test-client-secret';
}

// Usage in test setup
beforeAll(() => {
  setupTestEnvironment();
});
```

---

*This functions documentation provides comprehensive coverage of all utility functions, helper methods, and implementation details in the NestJS AWS Cognito authentication system. Each function includes implementation details, usage examples, and practical applications.*