import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let service: Record<string, jest.Mock>;

  beforeEach(async () => {
    service = {
      login: jest.fn(),
      signup: jest.fn(),
      confirmSignup: jest.fn(),
      resendConfirmationCode: jest.fn(),
      forgotPassword: jest.fn(),
      confirmForgotPassword: jest.fn(),
      changePassword: jest.fn(),
      requireNewPassword: jest.fn(),
      adminCreateUser: jest.fn(),
      adminDeleteUser: jest.fn(),
      listUsers: jest.fn(),
      adminGetUser: jest.fn(),
      getUser: jest.fn(),
      deleteUser: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [{ provide: AuthService, useValue: service }],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  afterEach(() => jest.clearAllMocks());

  const cases: Array<{
    name: string;
    controllerMethod: keyof AuthController;
    serviceMethod: keyof AuthService;
    dto: any;
    expectedArg?: any;
  }> = [
    {
      name: 'login',
      controllerMethod: 'login',
      serviceMethod: 'login',
      dto: { email: 'e', password: 'p' },
    },
    {
      name: 'signup',
      controllerMethod: 'signup',
      serviceMethod: 'signup',
      dto: { email: 'e', password: 'p' },
    },
    {
      name: 'confirmSignup',
      controllerMethod: 'confirmSignup',
      serviceMethod: 'confirmSignup',
      dto: { email: 'e', code: 'c' },
    },
    {
      name: 'resendConfirmationCode',
      controllerMethod: 'resendConfirmationCode',
      serviceMethod: 'resendConfirmationCode',
      dto: { email: 'e' },
    },
    {
      name: 'forgotPassword',
      controllerMethod: 'forgotPassword',
      serviceMethod: 'forgotPassword',
      dto: { email: 'e' },
      expectedArg: 'e',
    },
    {
      name: 'confirmForgotPassword',
      controllerMethod: 'confirmForgotPassword',
      serviceMethod: 'confirmForgotPassword',
      dto: { email: 'e', code: 'c', password: 'p' },
    },
    {
      name: 'changePassword',
      controllerMethod: 'changePassword',
      serviceMethod: 'changePassword',
      dto: { previousPassword: 'p', proposedPassword: 'n', accessToken: 't' },
    },
    {
      name: 'forceChangePassword',
      controllerMethod: 'forceChangePassword',
      serviceMethod: 'requireNewPassword',
      dto: { newPassword: 'n', session: 's', challengeResponses: {} },
    },
    {
      name: 'adminCreateUser',
      controllerMethod: 'adminCreateUser',
      serviceMethod: 'adminCreateUser',
      dto: { email: 'e' },
    },
    {
      name: 'adminDeleteUser',
      controllerMethod: 'adminDeleteUser',
      serviceMethod: 'adminDeleteUser',
      dto: { username: 'u' },
    },
    {
      name: 'listUsers',
      controllerMethod: 'listUsers',
      serviceMethod: 'listUsers',
      dto: { limit: 1 },
    },
    {
      name: 'adminGetUser',
      controllerMethod: 'adminGetUser',
      serviceMethod: 'adminGetUser',
      dto: { username: 'u' },
    },
    {
      name: 'getUser',
      controllerMethod: 'getUser',
      serviceMethod: 'getUser',
      dto: { accessToken: 't' },
    },
    {
      name: 'delete',
      controllerMethod: 'delete',
      serviceMethod: 'deleteUser',
      dto: { email: 'e', password: 'p' },
    },
  ];

  describe.each(cases)('$name', (testCase) => {
    it('returns service result', async () => {
      (service[testCase.serviceMethod as string] as jest.Mock).mockResolvedValue('ok');
      const result = await (controller as any)[testCase.controllerMethod](testCase.dto);
      expect(result).toBe('ok');
      expect(service[testCase.serviceMethod as string]).toHaveBeenCalledWith(
        testCase.expectedArg ?? testCase.dto,
      );
    });

    it('throws BadRequestException when service fails', async () => {
      (service[testCase.serviceMethod as string] as jest.Mock).mockRejectedValue(new Error('fail'));
      await expect(
        (controller as any)[testCase.controllerMethod](testCase.dto),
      ).rejects.toThrow(BadRequestException);
      expect(service[testCase.serviceMethod as string]).toHaveBeenCalledWith(
        testCase.expectedArg ?? testCase.dto,
      );
    });
  });
});

