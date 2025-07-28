# NestJS AWS Cognito Authentication System - Documentation

[![NestJS](https://img.shields.io/badge/NestJS-8.x-red.svg)](https://nestjs.com/)
[![AWS Cognito](https://img.shields.io/badge/AWS-Cognito-orange.svg)](https://aws.amazon.com/cognito/)
[![TypeScript](https://img.shields.io/badge/TypeScript-4.x-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

This documentation covers a comprehensive NestJS application that provides AWS Cognito authentication functionality. The system offers complete user management capabilities including registration, authentication, password management, and administrative functions.

## Features

- 🔐 **Complete Authentication Flow**: Login, signup, email verification
- 🔄 **Password Management**: Change password, forgot password, reset password
- 👥 **User Management**: Get user info, delete accounts
- 🛡️ **Admin Functions**: Create users, delete users, reset passwords, list users
- 🔑 **JWT Integration**: Secure token validation with AWS Cognito JWKS
- 🚀 **Production Ready**: Docker support, environment configuration
- 📱 **Frontend Integration**: React and Angular examples
- ✅ **Comprehensive Testing**: Unit tests, integration tests, mocks
- 📊 **Monitoring**: Health checks, performance monitoring, logging

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   NestJS API    │    │   AWS Cognito   │
│                 │    │                 │    │                 │
│ - React         │◄──►│ - Auth Module   │◄──►│ - User Pool     │
│ - Angular       │    │ - JWT Strategy  │    │ - JWKS Endpoint │
│ - Mobile App    │    │ - Controllers   │    │ - User Database │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Prerequisites

- Node.js 12+
- AWS Account with Cognito User Pool
- Environment variables configured

### 2. Installation

```bash
npm install
```

### 3. Configuration

Create a `.env` file:

```bash
AWS_COGNITO_REGION=us-east-1
AWS_COGNITO_USER_POOL_ID=us-east-1_xxxxxxxxx
AWS_COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 4. Run the Application

```bash
# Development
npm run start:dev

# Production
npm run start:prod
```

## Documentation Structure

### 📚 Core Documentation

| Document | Description | Key Topics |
|----------|-------------|------------|
| **[API Documentation](./API_DOCUMENTATION.md)** | Complete API reference with examples | Endpoints, DTOs, Request/Response formats |
| **[Component Documentation](./COMPONENT_DOCUMENTATION.md)** | Detailed component and service docs | Modules, Controllers, Services, Strategies |
| **[Functions Documentation](./FUNCTIONS_DOCUMENTATION.md)** | All utility functions and helpers | Authentication functions, Utilities, Validators |
| **[Usage Guide](./USAGE_GUIDE.md)** | Practical implementation guide | Frontend integration, Deployment, Best practices |

### 🚀 Getting Started

1. **Start Here**: [Usage Guide - Quick Start](./USAGE_GUIDE.md#quick-start)
2. **API Reference**: [API Documentation](./API_DOCUMENTATION.md)
3. **Component Details**: [Component Documentation](./COMPONENT_DOCUMENTATION.md)
4. **Functions Reference**: [Functions Documentation](./FUNCTIONS_DOCUMENTATION.md)

## API Endpoints Overview

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login` | User authentication |
| `POST` | `/auth/signup` | User registration |
| `POST` | `/auth/confirm-signup` | Email verification |
| `POST` | `/auth/resend-confirmation-code` | Resend verification code |

### Password Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/forgot-password` | Initiate password reset |
| `POST` | `/auth/confirm-forgot-password` | Complete password reset |
| `POST` | `/auth/change-password` | Change user password |
| `POST` | `/auth/require-new-password` | Handle temporary password |

### User Information

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/get-user` | Get user profile |
| `DELETE` | `/auth/user` | Delete user account |

### Administrative Functions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/admin-create-user` | Admin create user |
| `POST` | `/auth/admin-delete-user` | Admin delete user |
| `GET` | `/auth/admin-get-user` | Admin get user info |
| `POST` | `/auth/admin-reset-user-password` | Admin reset password |
| `GET` | `/auth/list-users` | List all users |

## Key Components

### Core Services

- **AuthService**: Main authentication business logic
- **JwtStrategy**: Token validation and user extraction
- **AuthController**: API endpoint handlers

### Data Transfer Objects (DTOs)

- **AuthenticateRequestDto**: Login credentials
- **SignupRequestDto**: User registration data
- **ConfirmSignupRequestDto**: Email verification
- **ChangePasswordRequestDto**: Password change
- **Admin DTOs**: Administrative operations

### Configuration

- **AuthModule**: Authentication module setup
- **AppModule**: Root application module
- **Environment Configuration**: AWS Cognito settings

## Frontend Integration Examples

### React Example

```typescript
// Quick authentication hook usage
const { login, logout, isAuthenticated } = useAuth();

const handleLogin = async () => {
  const success = await login(email, password);
  if (success) {
    // Redirect to protected route
  }
};
```

### Angular Example

```typescript
// Service injection and usage
constructor(private authService: AuthService) {}

login() {
  this.authService.login(email, password).subscribe(
    response => {
      // Handle successful login
    }
  );
}
```

## Testing

### Unit Tests

```bash
npm run test
```

### Test Coverage

```bash
npm run test:cov
```

### End-to-End Tests

```bash
npm run test:e2e
```

## Deployment

### Docker

```bash
# Build image
docker build -t nestjs-cognito-auth .

# Run container
docker run -p 3000:3000 nestjs-cognito-auth
```

### AWS Lambda

The application includes AWS Lambda deployment configuration for serverless deployment.

## Security Features

- 🔐 **JWT Token Validation**: RS256 algorithm with AWS Cognito JWKS
- 🛡️ **Rate Limiting**: Protection against brute force attacks
- 🔒 **Input Validation**: Comprehensive request validation
- 🚫 **CORS Configuration**: Cross-origin request security
- 📝 **Security Headers**: Protection headers for production

## Monitoring and Logging

- **Health Checks**: Application and AWS Cognito connectivity
- **Performance Monitoring**: Request duration tracking
- **Error Logging**: Comprehensive error tracking
- **Debug Logging**: Development debugging support

## Error Handling

The system provides comprehensive error handling for AWS Cognito specific errors:

- `UserNotConfirmedException`
- `NotAuthorizedException`
- `UserNotFoundException`
- `InvalidPasswordException`
- `CodeMismatchException`
- `ExpiredCodeException`

## Environment Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `AWS_COGNITO_REGION` | AWS region | ✅ |
| `AWS_COGNITO_USER_POOL_ID` | Cognito User Pool ID | ✅ |
| `AWS_COGNITO_CLIENT_ID` | Cognito App Client ID | ✅ |
| `AWS_COGNITO_CLIENT_SECRET` | Cognito App Client Secret | ✅ |
| `PORT` | Application port | ❌ |
| `NODE_ENV` | Environment (development/production) | ❌ |

## Troubleshooting

### Common Issues

1. **"NotAuthorizedException" Error**
   - Check SECRET_HASH generation
   - Verify client secret configuration
   - Ensure user pool settings

2. **CORS Issues**
   - Configure CORS origins correctly
   - Check preflight requests
   - Verify headers configuration

3. **JWT Validation Errors**
   - Verify JWKS endpoint accessibility
   - Check token expiration
   - Validate audience and issuer

### Debug Mode

Enable debug logging in development:

```bash
NODE_ENV=development npm run start:dev
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Best Practices

### Security

- Use HTTPS in production
- Implement rate limiting
- Validate all inputs
- Store secrets securely
- Enable CORS appropriately

### Performance

- Implement caching for JWKS
- Use connection pooling
- Monitor response times
- Optimize database queries

### Maintainability

- Follow TypeScript best practices
- Write comprehensive tests
- Document all public APIs
- Use consistent error handling

## Version Compatibility

| Component | Version | Notes |
|-----------|---------|-------|
| NestJS | 8.x | Core framework |
| AWS SDK | 3.x | Latest AWS SDK for JavaScript |
| Node.js | 12+ | Minimum supported version |
| TypeScript | 4.x | Type safety |

## Support and Resources

### Documentation Links

- [NestJS Documentation](https://docs.nestjs.com/)
- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [JWT Documentation](https://jwt.io/introduction/)

### Community

- [NestJS Discord](https://discord.gg/nestjs)
- [AWS Developer Forums](https://forums.aws.amazon.com/)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/nestjs)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v1.0.0
- Initial release
- Complete AWS Cognito integration
- JWT authentication strategy
- Frontend integration examples
- Comprehensive documentation

---

## Quick Navigation

| 📖 **Documentation** | 🚀 **Implementation** | 🔧 **Development** |
|----------------------|------------------------|---------------------|
| [API Docs](./API_DOCUMENTATION.md) | [Usage Guide](./USAGE_GUIDE.md) | [Component Docs](./COMPONENT_DOCUMENTATION.md) |
| [Functions Ref](./FUNCTIONS_DOCUMENTATION.md) | [Quick Start](./USAGE_GUIDE.md#quick-start) | [Testing](./COMPONENT_DOCUMENTATION.md#testing-components) |

*This documentation provides complete coverage of the NestJS AWS Cognito authentication system. Start with the [Usage Guide](./USAGE_GUIDE.md) for practical implementation examples.*