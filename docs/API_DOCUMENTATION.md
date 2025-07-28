# AWS Cognito NestJS API Documentation

## Overview

This is a comprehensive NestJS application that provides AWS Cognito authentication functionality. The API offers complete user management capabilities including registration, authentication, password management, and administrative functions.

## Table of Contents

- [Getting Started](#getting-started)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Data Transfer Objects (DTOs)](#data-transfer-objects-dtos)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [Configuration](#configuration)

## Getting Started

### Prerequisites

- Node.js 12+
- AWS Account with Cognito User Pool configured
- Environment variables configured (see [Configuration](#configuration))

### Installation

```bash
npm install
```

### Running the Application

```bash
# Development
npm run start:dev

# Production
npm run start:prod

# Build
npm run build
```

The application runs on port 3000 by default.

## Authentication

This API uses AWS Cognito for user authentication. The authentication flow includes:

1. **User Registration** - Create new user accounts
2. **Email/SMS Verification** - Confirm user registration
3. **User Login** - Authenticate and receive access tokens
4. **Password Management** - Change and reset passwords
5. **Administrative Functions** - Admin-level user management

### JWT Strategy

The application uses JWT strategy with AWS Cognito for token validation:
- **Algorithm**: RS256
- **Token Source**: Authorization Bearer header
- **JWKS Endpoint**: `https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`

## API Endpoints

### User Authentication

#### 1. User Login
- **Endpoint**: `POST /auth/login`
- **Description**: Authenticate user with email and password
- **Request Body**: `AuthenticateRequestDto`
- **Response**: Cognito authentication response with access tokens

**Example Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Example Response:**
```json
{
  "AuthenticationResult": {
    "AccessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "IdToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "RefreshToken": "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ...",
    "TokenType": "Bearer",
    "ExpiresIn": 3600
  }
}
```

#### 2. User Registration
- **Endpoint**: `POST /auth/signup`
- **Description**: Register a new user account
- **Request Body**: `SignupRequestDto`
- **Response**: User confirmation status

**Example Request:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "phone_number": "+1234567890",
  "name": "John Doe",
  "gender": "male",
  "birthdate": "1990-01-01",
  "address": "123 Main St",
  "scope": "email"
}
```

#### 3. Confirm User Registration
- **Endpoint**: `POST /auth/confirm-signup`
- **Description**: Confirm user registration with verification code
- **Request Body**: `ConfirmSignupRequestDto`
- **Response**: Confirmation status

**Example Request:**
```json
{
  "email": "newuser@example.com",
  "code": "123456"
}
```

#### 4. Resend Confirmation Code
- **Endpoint**: `POST /auth/resend-confirmation-code`
- **Description**: Resend verification code to user
- **Request Body**: `ResendConfirmationCodeRequestDto`
- **Response**: Confirmation delivery details

**Example Request:**
```json
{
  "email": "user@example.com"
}
```

### Password Management

#### 5. Forgot Password
- **Endpoint**: `POST /auth/forgot-password`
- **Description**: Initiate password reset process
- **Request Body**: `{ "email": "user@example.com" }`
- **Response**: Password reset initiation status

**Example Request:**
```json
{
  "email": "user@example.com"
}
```

#### 6. Confirm Forgot Password
- **Endpoint**: `POST /auth/confirm-forgot-password`
- **Description**: Complete password reset with verification code
- **Request Body**: `ConfirmForgotPasswordRequestDto`
- **Response**: Password reset confirmation

**Example Request:**
```json
{
  "email": "user@example.com",
  "code": "123456",
  "password": "NewSecurePassword123!"
}
```

#### 7. Change Password
- **Endpoint**: `POST /auth/change-password`
- **Description**: Change password for authenticated user
- **Request Body**: `ChangePasswordRequestDto`
- **Response**: Password change confirmation

**Example Request:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "previous_password": "OldPassword123!",
  "proposed_password": "NewPassword123!"
}
```

#### 8. Require New Password
- **Endpoint**: `POST /auth/require-new-password`
- **Description**: Set new password when required (temporary password flow)
- **Request Body**: `RequireNewPasswordRequestDto`
- **Response**: New password confirmation

**Example Request:**
```json
{
  "email": "user@example.com",
  "password": "NewPassword123!",
  "session": "AYABeGuN..."
}
```

### User Information

#### 9. Get User Profile
- **Endpoint**: `GET /auth/get-user`
- **Description**: Get current user information
- **Request Body**: `GetUserRequestDto`
- **Response**: User profile information

**Example Request:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### 10. Delete User Account
- **Endpoint**: `DELETE /auth/user`
- **Description**: Delete user account
- **Request Body**: `AuthenticateRequestDto`
- **Response**: Deletion confirmation

**Example Request:**
```json
{
  "email": "user@example.com",
  "password": "UserPassword123!"
}
```

### Administrative Functions

#### 11. Admin Create User
- **Endpoint**: `POST /auth/admin-create-user`
- **Description**: Create user account (admin function)
- **Request Body**: `AdminCreateUserRequestDto`
- **Response**: User creation details

**Example Request:**
```json
{
  "email": "newuser@example.com",
  "message_action": "SUPPRESS"
}
```

#### 12. Admin Delete User
- **Endpoint**: `POST /auth/admin-delete-user`
- **Description**: Delete user account (admin function)
- **Request Body**: `AdminDeleteUserRequestDto`
- **Response**: Deletion confirmation

**Example Request:**
```json
{
  "email": "user@example.com"
}
```

#### 13. Admin Get User
- **Endpoint**: `GET /auth/admin-get-user`
- **Description**: Get user information (admin function)
- **Request Body**: `AdminGetUserRequestDto`
- **Response**: Complete user information

**Example Request:**
```json
{
  "email": "user@example.com"
}
```

#### 14. Admin Reset User Password
- **Endpoint**: `POST /auth/admin-reset-user-password`
- **Description**: Reset user password (admin function)
- **Request Body**: `AdminResetUserPasswordRequestDto`
- **Response**: Password reset confirmation

**Example Request:**
```json
{
  "email": "user@example.com"
}
```

#### 15. List Users
- **Endpoint**: `GET /auth/list-users`
- **Description**: List all users (admin function)
- **Request Body**: `ListUsersRequestDto`
- **Response**: Paginated list of users

**Example Request:**
```json
{
  "attributes": ["email", "name"],
  "filter": "",
  "limit": 10,
  "pagination_token": ""
}
```

## Data Transfer Objects (DTOs)

### AuthenticateRequestDto
```typescript
{
  email: string;      // User email address
  password: string;   // User password
}
```

### SignupRequestDto
```typescript
{
  email: string;        // User email address (required)
  password: string;     // User password (required)
  phone_number: string; // User phone number
  name: string;         // Full name
  gender: string;       // Gender
  birthdate: string;    // Birth date (YYYY-MM-DD)
  address: string;      // Physical address
  scope: string;        // OAuth scope
}
```

### ConfirmSignupRequestDto
```typescript
{
  email: string;  // User email address
  code: string;   // Verification code from email/SMS
}
```

### ResendConfirmationCodeRequestDto
```typescript
{
  email: string;  // User email address
}
```

### ConfirmForgotPasswordRequestDto
```typescript
{
  email: string;     // User email address
  code: string;      // Verification code from email/SMS
  password: string;  // New password
}
```

### ChangePasswordRequestDto
```typescript
{
  access_token: string;        // Current access token
  previous_password: string;   // Current password
  proposed_password: string;   // New password
}
```

### RequireNewPasswordRequestDto
```typescript
{
  email: string;     // User email address
  password: string;  // New password
  session: string;   // Session token from login challenge
}
```

### GetUserRequestDto
```typescript
{
  access_token: string;  // Current access token
}
```

### AdminCreateUserRequestDto
```typescript
{
  email: string;                    // User email address
  message_action: "RESEND" | "SUPPRESS";  // Message action type
}
```

### AdminDeleteUserRequestDto
```typescript
{
  email: string;  // User email address
}
```

### AdminGetUserRequestDto
```typescript
{
  email: string;  // User email address
}
```

### AdminResetUserPasswordRequestDto
```typescript
{
  email: string;  // User email address
}
```

### ListUsersRequestDto
```typescript
{
  attributes: string[];      // Array of attributes to return
  filter: string;           // Filter expression
  limit: number;            // Maximum number of users to return
  pagination_token: string; // Token for pagination
}
```

## Error Handling

All endpoints return errors in a consistent format:

```json
{
  "statusCode": 400,
  "message": "Error description",
  "error": "Bad Request"
}
```

### Common Error Responses

- **400 Bad Request**: Invalid request parameters or format
- **401 Unauthorized**: Invalid credentials or expired tokens
- **403 Forbidden**: Insufficient permissions
- **500 Internal Server Error**: AWS Cognito or server errors

### AWS Cognito Specific Errors

The API may return AWS Cognito error names directly:
- `UserNotConfirmedException`
- `NotAuthorizedException`
- `UserNotFoundException`
- `InvalidPasswordException`
- `CodeMismatchException`
- `ExpiredCodeException`

## Configuration

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```bash
# AWS Cognito Configuration
AWS_COGNITO_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
AWS_COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### AWS Cognito Setup

1. Create a User Pool in AWS Cognito
2. Configure authentication flow settings
3. Set up attributes and verification methods
4. Create an App Client (without client secret for JS SDK compatibility)
5. Note down the User Pool ID and Client ID

## Examples

### Complete User Registration Flow

```javascript
// 1. Register user
const signupResponse = await fetch('/auth/signup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePassword123!',
    name: 'John Doe'
  })
});

// 2. Confirm registration with code
const confirmResponse = await fetch('/auth/confirm-signup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    code: '123456'
  })
});

// 3. Login user
const loginResponse = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePassword123!'
  })
});

const tokens = await loginResponse.json();
```

### Password Reset Flow

```javascript
// 1. Initiate password reset
await fetch('/auth/forgot-password', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com'
  })
});

// 2. Confirm password reset with code
await fetch('/auth/confirm-forgot-password', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    code: '123456',
    password: 'NewPassword123!'
  })
});
```

### Using Access Tokens

```javascript
// Get user profile
const userResponse = await fetch('/auth/get-user', {
  method: 'GET',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    access_token: accessToken
  })
});

// Change password
await fetch('/auth/change-password', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    access_token: accessToken,
    previous_password: 'OldPassword123!',
    proposed_password: 'NewPassword123!'
  })
});
```

## Testing

### Postman Collection

A Postman collection is available at `./postman/nestjs-aws-cognito.postman_collection.json` for testing all API endpoints.

### Unit Tests

Run the test suite:

```bash
# Unit tests
npm run test

# Test coverage
npm run test:cov

# End-to-end tests
npm run test:e2e
```

## Security Considerations

1. **Environment Variables**: Never commit AWS credentials to version control
2. **HTTPS**: Always use HTTPS in production
3. **Token Validation**: JWT tokens are validated using AWS Cognito's JWKS endpoint
4. **Password Policy**: Configure strong password policies in AWS Cognito
5. **Rate Limiting**: Implement rate limiting for authentication endpoints
6. **CORS**: Configure CORS appropriately for your frontend application

## Support

For issues and questions:
1. Check AWS Cognito documentation
2. Review the error messages and HTTP status codes
3. Ensure environment variables are correctly configured
4. Verify AWS Cognito User Pool settings

---

*This documentation covers the complete AWS Cognito NestJS authentication API. For additional features or customizations, refer to the source code and AWS Cognito documentation.*