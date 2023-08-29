import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { UserController } from './user/user.controller';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true
      // envFilePath: 'src/config/config.env'
    }),
    AuthModule,
    PrismaModule,
    UserModule
  ],
  controllers: [UserController],
  providers: []
})
export class AppModule {}
