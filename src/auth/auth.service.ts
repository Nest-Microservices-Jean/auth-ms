import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Connected to the database :)');
  }

  async singJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const payload = this.jwtService.verify(token, {
        secret: envs.JWT_SECRET,
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = payload;
      return {
        user,
        token: await this.singJWT(user),
      };
    } catch (error) {
      throw new RpcException({ status: 401, message: 'Invalid token' });
    }
  }

  async registerUser(registerUser: RegisterUserDto) {
    const { email, password, name } = registerUser;
    try {
      const user = await this.user.findFirst({
        where: {
          email: email,
        },
      });

      if (user) {
        throw new RpcException({ status: 400, message: 'User already exists' });
      }

      const newUser = await this.user.create({
        data: {
          name: name,
          email: email,
          password: bcrypt.hashSync(password, 10), // hash password
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...rest } = newUser;

      return { user: rest, token: await this.singJWT(rest) };
    } catch (error) {
      throw new RpcException({ status: 400, message: error.message });
    }
  }

  async loginUser(loginUser: LoginUserDto) {
    const { email, password } = loginUser;
    try {
      const user = await this.user.findFirst({
        where: {
          email: email,
        },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'Use/Password not valid',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'Use/Password not valid',
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...rest } = user;

      return { user: rest, token: await this.singJWT(rest) };
    } catch (error) {
      throw new RpcException({ status: 400, message: error.message });
    }
  }
}
