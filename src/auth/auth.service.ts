import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto, LoginUserDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt/dist';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}

  async signup(createUserDto: CreateUserDto) {
    const hash = await argon.hash(createUserDto.password);
    try {
      const newUser = await this.prisma.user.create({
        data: {
          email: createUserDto.email,
          username: createUserDto.username,
          passwordHash: hash,
          firstName: createUserDto.firstName,
          lastName: createUserDto.lastName,
          imageURL: createUserDto.imageURL,
          mobileNum: createUserDto.mobileNum
        }
      });

      return { msg: 'Signed up', newUser };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        // Credential already taken
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            `This ${error.meta.target[0]} is already taken`
          );
        }
      }
      throw error;
    }
  }

  async signin(loginUserDto: LoginUserDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: loginUserDto.email }
    });

    if (!user) {
      throw new NotFoundException(`The user doesn't exist`);
    }

    const pwMatches = await argon.verify(
      user.passwordHash,
      loginUserDto.password
    );

    if (!pwMatches) {
      throw new UnauthorizedException('Email or Password is incorrect');
    }

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userID: string,
    email: string
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userID,
      email
    };

    const secret = this.config.get('JWT_SECRET');

    const accessToken = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret
    });

    return {
      access_token: accessToken
    };
  }
}
