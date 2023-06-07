import { Module, forwardRef } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserModule } from 'src/feature/user/user.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { CryptoUtil } from 'src/common/utils/crypto.util';
import { JwtStrategy } from './jwt.strategy';
import { AuthController } from './auth.controller';

@Module({
  imports:[
    JwtModule.register({
      secret:jwtConstants.secret,
      signOptions:{
        expiresIn:"1h",
      }
    }),
    forwardRef(()=>UserModule),
    PassportModule,
  ],
  controllers:[
    AuthController
  ],
  providers: [AuthService,LocalStrategy,JwtStrategy,CryptoUtil],
  exports:[AuthService]
})
export class AuthModule {}
