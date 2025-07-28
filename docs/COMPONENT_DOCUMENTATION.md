# Component Documentation

## Overview

This document provides comprehensive documentation for all components, services, controllers, and modules in the NestJS AWS Cognito authentication system.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Modules](#modules)
- [Controllers](#controllers)
- [Services](#services)
- [Authentication Strategy](#authentication-strategy)
- [Data Transfer Objects](#data-transfer-objects)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)

## Architecture Overview

The application follows NestJS modular architecture with the following structure:

```
src/
├── app.module.ts           # Root application module
├── app.controller.ts       # Root application controller
├── app.service.ts          # Root application service
├── main.ts                 # Application bootstrap
└── auth/                   # Authentication module
    ├── auth.module.ts      # Authentication module definition
    ├── auth.controller.ts  # Authentication endpoints
    ├── auth.service.ts     # Authentication business logic
    ├── auth.config.ts      # Configuration setup
    ├── jwt.strategy.ts     # JWT authentication strategy
    └── dto/                # Data Transfer Objects
        ├── *.request.dto.ts
        └── ...
```

## Modules

### AppModule

**File**: `src/app.module.ts`

The root module that orchestrates the entire application.

```typescript
@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot({
      isGlobal: true,
      load: [authconfig],
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

**Features:**
- Imports the `AuthModule` for authentication functionality
- Configures global `ConfigModule` with AWS Cognito settings
- Provides root application controller and service

**Dependencies:**
- `AuthModule`: Authentication functionality
- `ConfigModule`: Configuration management
- `authconfig`: AWS Cognito configuration

### AuthModule

**File**: `src/auth/auth.module.ts`

Dedicated module for authentication-related functionality.

```typescript
@Module({
  imports: [ConfigModule, PassportModule.register({ defaultStrategy: 'jwt' })],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
```

**Features:**
- Configures Passport.js with JWT strategy as default
- Provides authentication service and JWT strategy
- Exposes authentication controller endpoints

**Dependencies:**
- `ConfigModule`: Configuration access
- `PassportModule`: Authentication middleware
- `AuthService`: Core authentication logic
- `JwtStrategy`: JWT token validation
- `AuthController`: API endpoints

## Controllers

### AppController

**File**: `src/app.controller.ts`

Basic root controller providing application health check.

```typescript
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
```

### AuthController

**File**: `src/auth/auth.controller.ts`

Main authentication controller handling all AWS Cognito operations.

```typescript
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  
  // ... endpoint methods
}
```

#### Methods

##### `login(authenticateRequest: AuthenticateRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/login`
- **Purpose**: Authenticate user and return access tokens
- **Parameters**: 
  - `authenticateRequest`: User credentials
- **Returns**: AWS Cognito authentication result
- **Error Handling**: Catches exceptions and returns BadRequestException

**Example:**
```typescript
@Post('login')
async login(@Body() authenticateRequest: AuthenticateRequestDto) {
  try {
    return await this.authService.login(authenticateRequest);
  } catch (e) {
    throw new BadRequestException(e.message);
  }
}
```

##### `signup(signupRequest: SignupRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/signup`
- **Purpose**: Register new user account
- **Parameters**: 
  - `signupRequest`: User registration data
- **Returns**: User confirmation status
- **Error Handling**: Catches exceptions and returns BadRequestException

##### `confirmSignup(confirmSignupRequest: ConfirmSignupRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/confirm-signup`
- **Purpose**: Confirm user registration with verification code
- **Parameters**: 
  - `confirmSignupRequest`: Email and verification code
- **Returns**: Confirmation status

##### `resendConfirmationCode(resendConfirmationCodeRequest: ResendConfirmationCodeRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/resend-confirmation-code`
- **Purpose**: Resend verification code to user
- **Parameters**: 
  - `resendConfirmationCodeRequest`: User email
- **Returns**: Resend confirmation details

##### `forgotPassword(data: any)`

- **HTTP Method**: POST
- **Route**: `/auth/forgot-password`
- **Purpose**: Initiate password reset process
- **Parameters**: 
  - `data`: Object containing user email
- **Returns**: Password reset initiation status

##### `confirmForgotPassword(confirmForgotPassword: ConfirmForgotPasswordRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/confirm-forgot-password`
- **Purpose**: Complete password reset with verification code
- **Parameters**: 
  - `confirmForgotPassword`: Email, code, and new password
- **Returns**: Password reset confirmation

##### `changePassword(changePasswordRequest: ChangePasswordRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/change-password`
- **Purpose**: Change password for authenticated user
- **Parameters**: 
  - `changePasswordRequest`: Access token and passwords
- **Returns**: Password change confirmation

##### `forceChangePassword(requireNewPasswordRequest: RequireNewPasswordRequestDto)`

- **HTTP Method**: POST
- **Route**: `/auth/require-new-password`
- **Purpose**: Handle temporary password challenge
- **Parameters**: 
  - `requireNewPasswordRequest`: Session and new password
- **Returns**: Password update confirmation

##### Administrative Methods

**Admin Create User:**
```typescript
@Post('admin-create-user')
async adminCreateUser(@Body() adminCreateUserRequest: AdminCreateUserRequestDto)
```

**Admin Delete User:**
```typescript
@Post('admin-delete-user')
async adminDeleteUser(@Body() adminDeleteUserRequest: AdminDeleteUserRequestDto)
```

**List Users:**
```typescript
@Get('list-users')
async listUsers(@Body() listUsersRequest: ListUsersRequestDto)
```

**Admin Get User:**
```typescript
@Get('admin-get-user')
async adminGetUser(@Body() adminGetUserRequest: AdminGetUserRequestDto)
```

**Get User:**
```typescript
@Get('get-user')
async getUser(@Body() getUserRequest: GetUserRequestDto)
```

**Delete User:**
```typescript
@Delete('user')
async delete(@Body() authenticateRequest: AuthenticateRequestDto)
```

**Admin Reset User Password:**
```typescript
@Post('admin-reset-user-password')
async adminResetUserPassword(@Body() adminResetUserPasswordRequest: AdminResetUserPasswordRequestDto)
```

## Services

### AppService

**File**: `src/app.service.ts`

Simple service providing basic application functionality.

```typescript
@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
}
```

### AuthService

**File**: `src/auth/auth.service.ts`

Core authentication service handling AWS Cognito operations.

```typescript
@Injectable()
export class AuthService {
  private readonly client: CognitoIdentityProviderClient;
  private readonly clientId: string;
  private readonly userPoolId: string;

  constructor(private readonly configService: ConfigService) {
    // AWS Cognito client initialization
  }
}
```

#### Constructor

Initializes AWS Cognito client and configuration:

```typescript
constructor(private readonly configService: ConfigService) {
  this.client = new CognitoIdentityProviderClient({
    region: process.env.AWS_COGNITO_REGION,
  });
  this.clientId = process.env.AWS_COGNITO_CLIENT_ID;
  this.userPoolId = process.env.AWS_COGNITO_USER_POOL_ID;
}
```

#### Public Methods

##### `login(user: AuthenticateRequestDto)`

Authenticates user using AWS Cognito's InitiateAuth command.

**Implementation Details:**
- Generates SECRET_HASH for enhanced security
- Uses USER_PASSWORD_AUTH flow
- Returns complete authentication result including tokens
- Handles various authentication challenges

**Code Example:**
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
    // Error handling
  }
}
```

##### `signup(signupRequest: SignupRequestDto, attributes?: Record<string, string>)`

Registers new user with AWS Cognito.

**Features:**
- Accepts user attributes as optional parameter
- Automatically sets email verification
- Formats attributes for Cognito compatibility
- Returns user confirmation status

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
    // Error handling
  }
}
```

##### `confirmSignup(confirmSignup: ConfirmSignupRequestDto)`

Confirms user registration using verification code.

##### `resendConfirmationCode(resendConfirmationCode: ResendConfirmationCodeRequestDto)`

Resends verification code to user's email/phone.

##### `forgotPassword(email: string)`

Initiates password reset process.

##### `confirmForgotPassword(confirmForgotPassword: ConfirmForgotPasswordRequestDto)`

Completes password reset with verification code and new password.

##### `changePassword(changePassword: ChangePasswordRequestDto)`

Changes password for authenticated user using access token.

##### `requireNewPassword(requireNewPassword: RequireNewPasswordRequestDto)`

Handles NEW_PASSWORD_REQUIRED challenge response.

**Administrative Methods:**

##### `adminCreateUser(adminCreateUser: AdminCreateUserRequestDto)`

Creates user account with admin privileges.

##### `adminDeleteUser(adminDeleteUser: AdminDeleteUserRequestDto)`

Deletes user account with admin privileges.

##### `listUsers(listUsers: ListUsersRequestDto)`

Lists users with filtering and pagination support.

##### `adminGetUser(adminGetUser: AdminGetUserRequestDto)`

Retrieves complete user information with admin privileges.

##### `getUser(getUser: GetUserRequestDto)`

Retrieves user information using access token.

##### `deleteUser(user: AuthenticateRequestDto)`

Deletes user account.

##### `adminResetUserPassword(adminResetUserPassword: AdminResetUserPasswordRequestDto)`

Resets user password with admin privileges.

#### Private Methods

##### `formatAttributes(attributes: Record<string, string>)`

Converts key-value attributes to Cognito format:

```typescript
private formatAttributes(attributes: Record<string, string>): Array<{ Name: string; Value: string }> {
  return Object.entries(attributes).map(([key, value]) => ({
    Name: key,
    Value: value,
  }));
}
```

##### `setUserAttributes(email: string, attributes: Record<string, string>)`

Sets user attributes (placeholder for AdminUpdateUserAttributes implementation).

##### `cognitoSecretHash(username: string)`

Generates SECRET_HASH for AWS Cognito authentication:

```typescript
private cognitoSecretHash(username: string): string {
  const secret = process.env.AWS_COGNITO_CLIENT_SECRET;
  const message = username + this.clientId;
  
  return crypto.createHmac('sha256', secret).update(message).digest('base64');
}
```

## Authentication Strategy

### JwtStrategy

**File**: `src/auth/jwt.strategy.ts`

Passport JWT strategy for validating AWS Cognito tokens.

```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly authService: AuthService,
    private configService: ConfigService,
  ) {
    super({
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${configService.get<string>('authority')}/.well-known/jwks.json`,
      }),
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      audience: configService.get<string>('clientId'),
      issuer: configService.get<string>('authority'),
      algorithms: ['RS256'],
    });
  }

  public async validate(payload: any) {
    return payload;
  }
}
```

**Features:**
- **JWKS Integration**: Automatically fetches public keys from AWS Cognito
- **Token Extraction**: Extracts JWT from Authorization Bearer header
- **Algorithm**: Uses RS256 for token verification
- **Caching**: Caches JWKS for performance
- **Rate Limiting**: Limits JWKS requests per minute

**Configuration Parameters:**
- `cache: true`: Enable JWKS caching
- `rateLimit: true`: Enable rate limiting
- `jwksRequestsPerMinute: 5`: Maximum JWKS requests per minute
- `algorithms: ['RS256']`: Supported signing algorithms

## Data Transfer Objects

### Base Authentication DTOs

#### AuthenticateRequestDto
```typescript
export class AuthenticateRequestDto {
  password: string;  // User password
  email: string;     // User email address
}
```

#### SignupRequestDto
```typescript
export class SignupRequestDto {
  password: string;     // User password (required)
  email: string;        // User email address (required)
  phone_number: string; // User phone number
  name: string;         // Full name
  gender: string;       // Gender
  birthdate: string;    // Birth date (YYYY-MM-DD format)
  address: string;      // Physical address
  scope: string;        // OAuth scope
}
```

### Verification DTOs

#### ConfirmSignupRequestDto
```typescript
export class ConfirmSignupRequestDto {
  code: string;   // Verification code from email/SMS
  email: string;  // User email address
}
```

#### ResendConfirmationCodeRequestDto
```typescript
export class ResendConfirmationCodeRequestDto {
  email: string;  // User email address
}
```

### Password Management DTOs

#### ChangePasswordRequestDto
```typescript
export class ChangePasswordRequestDto {
  access_token: string;        // Current valid access token
  previous_password: string;   // Current password
  proposed_password: string;   // New password
}
```

#### ConfirmForgotPasswordRequestDto
```typescript
export class ConfirmForgotPasswordRequestDto {
  email: string;     // User email address
  code: string;      // Verification code from email/SMS
  password: string;  // New password
}
```

#### RequireNewPasswordRequestDto
```typescript
export class RequireNewPasswordRequestDto {
  email: string;     // User email address
  password: string;  // New password
  session: string;   // Session token from authentication challenge
}
```

### User Information DTOs

#### GetUserRequestDto
```typescript
export class GetUserRequestDto {
  access_token: string;  // Valid access token
}
```

### Administrative DTOs

#### AdminCreateUserRequestDto
```typescript
export class AdminCreateUserRequestDto {
  email: string;                           // User email address
  message_action: "RESEND" | "SUPPRESS";   // Message action type
}
```

#### AdminDeleteUserRequestDto
```typescript
export class AdminDeleteUserRequestDto {
  email: string;  // User email address
}
```

#### AdminGetUserRequestDto
```typescript
export class AdminGetUserRequestDto {
  email: string;  // User email address
}
```

#### AdminResetUserPasswordRequestDto
```typescript
export class AdminResetUserPasswordRequestDto {
  email: string;  // User email address
}
```

#### ListUsersRequestDto
```typescript
export class ListUsersRequestDto {
  attributes: string[];      // Array of user attributes to return
  filter: string;           // Filter expression (Cognito filter syntax)
  limit: number;            // Maximum number of users to return
  pagination_token: string; // Token for pagination (from previous response)
}
```

## Configuration

### Auth Configuration

**File**: `src/auth/auth.config.ts`

Configuration factory for AWS Cognito settings:

```typescript
export default () => ({
  userPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
  clientId: process.env.AWS_COGNITO_CLIENT_ID,
  region: process.env.AWS_COGNITO_REGION,
  authority: `https://cognito-idp.${process.env.AWS_COGNITO_REGION}.amazonaws.com/${process.env.AWS_COGNITO_USER_POOL_ID}`,
});
```

**Properties:**
- `userPoolId`: AWS Cognito User Pool ID
- `clientId`: AWS Cognito App Client ID
- `region`: AWS region for Cognito service
- `authority`: Complete authority URL for JWKS and token validation

## Usage Examples

### Service Integration

#### Injecting AuthService

```typescript
import { Injectable } from '@nestjs/common';
import { AuthService } from './auth/auth.service';

@Injectable()
export class MyService {
  constructor(private readonly authService: AuthService) {}

  async authenticateUser(email: string, password: string) {
    return await this.authService.login({ email, password });
  }
}
```

#### Using JWT Strategy

```typescript
import { UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Controller('protected')
export class ProtectedController {
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req) {
    return req.user; // JWT payload
  }
}
```

### Custom Decorators

#### Creating User Decorator

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

**Usage:**
```typescript
@UseGuards(AuthGuard('jwt'))
@Get('profile')
getUserProfile(@User() user: any) {
  return user;
}
```

### Error Handling Patterns

#### Custom Exception Filter

```typescript
import { ExceptionFilter, Catch, ArgumentsHost, HttpStatus } from '@nestjs/common';
import { Response } from 'express';

@Catch()
export class CognitoExceptionFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';

    if (exception.name === 'UserNotConfirmedException') {
      status = HttpStatus.UNAUTHORIZED;
      message = 'User email not confirmed';
    } else if (exception.name === 'NotAuthorizedException') {
      status = HttpStatus.UNAUTHORIZED;
      message = 'Invalid credentials';
    }

    response.status(status).json({
      statusCode: status,
      message,
      timestamp: new Date().toISOString(),
    });
  }
}
```

### Testing Components

#### Unit Testing AuthService

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const config = {
                'AWS_COGNITO_REGION': 'us-east-1',
                'AWS_COGNITO_USER_POOL_ID': 'us-east-1_test',
                'AWS_COGNITO_CLIENT_ID': 'test-client-id',
              };
              return config[key];
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
```

#### Integration Testing AuthController

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            login: jest.fn(),
            signup: jest.fn(),
            confirmSignup: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
```

---

*This component documentation provides comprehensive coverage of all classes, methods, and usage patterns in the NestJS AWS Cognito authentication system. For implementation details, refer to the source code files.*