import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { AdminResetUserPasswordRequestDto } from './dto/adminresetuserpassword.request.dto';
import { AdminResetUserPasswordCommand } from '@aws-sdk/client-cognito-identity-provider';
import { HttpException } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let mockClient: { send: jest.Mock };
  let configService: ConfigService;

  beforeEach(() => {
    mockClient = { send: jest.fn() };
    configService = {
      get: jest.fn(),
    } as any;
    process.env.AWS_COGNITO_REGION = 'us-east-1';
    process.env.AWS_COGNITO_CLIENT_ID = 'clientId';
    process.env.AWS_COGNITO_USER_POOL_ID = 'userPoolId';
    service = new AuthService(configService);
    (service as any).client = mockClient;
    (service as any).userPoolId = 'userPoolId';
  });

  describe('adminResetUserPassword', () => {
    it('should call send with AdminResetUserPasswordCommand and return response', async () => {
      const dto: AdminResetUserPasswordRequestDto = {
        email: 'test@example.com',
      };
      const response = { success: true };
      mockClient.send.mockResolvedValue(response);
      const result = await service.adminResetUserPassword(dto);
      expect(mockClient.send).toHaveBeenCalledWith(
        expect.any(AdminResetUserPasswordCommand),
      );
      expect(result).toBe(response);
    });

    it('should return error name if error has name', async () => {
      const dto: AdminResetUserPasswordRequestDto = {
        email: 'test@example.com',
      };
      const error = { name: 'SomeError', message: 'fail' };
      mockClient.send.mockRejectedValue(error);
      const result = await service.adminResetUserPassword(dto);
      expect(result).toBe('SomeError');
    });

    it('should throw HttpException if error has no name', async () => {
      const dto: AdminResetUserPasswordRequestDto = {
        email: 'test@example.com',
      };
      const error = { message: 'fail' };
      mockClient.send.mockRejectedValue(error);
      await expect(service.adminResetUserPassword(dto)).rejects.toBeInstanceOf(
        HttpException,
      );
    });
  });
});
