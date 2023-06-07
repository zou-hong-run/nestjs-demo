import { Injectable } from '@nestjs/common';
import { UserService } from '../../feature/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { CryptoUtil } from 'src/common/utils/crypto.util';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService:UserService,
        private readonly jwtService:JwtService,
        private readonly cryptoUtil:CryptoUtil
    ){
        // console.log("autservice init");
    }

    async validateUser(account:string,pass:string):Promise<any>{
        
        // 给密码加密!!! 因为我们存用户的时候 密码是加密存储的 需要将输入的密码加密后才能验证
        let enPassword = this.cryptoUtil.encryptPassword(pass);

        // console.log("auth service validateUser enter",account,enPassword);
        const user = await this.userService.findOne(account);
        // console.log("auth service validateUser leave",user);
        if(user && user.password === enPassword){
            const {password,...result} = user;
            return result;
        }
        return null
    }

    // jwt签名用
    async login(user:any){
        const payload = {account:user.username,userId:user.id};
        return {
            access_token:this.jwtService.sign(payload)
        }
    }

}
