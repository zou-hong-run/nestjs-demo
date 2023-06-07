import { Module, forwardRef } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { CommonModule } from 'src/common/common.module';
import { AuthModule } from 'src/core/auth/auth.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from 'src/core/auth/local.strategy';

@Module({
  imports:[
    TypeOrmModule.forFeature([User]),
    forwardRef(()=>AuthModule),// 处理相互循环依赖
    CommonModule,
    PassportModule
  ],
  controllers: [UserController],
  providers: [
    UserService
  ],
  exports:[
    UserService,
  ]
})
export class UserModule {}
