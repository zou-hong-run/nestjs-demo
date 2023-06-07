// 本地策略

import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from '@nestjs/passport'
import { Strategy } from "passport-local";
import { AuthService } from "./auth.service";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy){
    
    constructor(
        private readonly authService:AuthService
    ){
        // console.log("local strategy init");
        super({
            usernameField: 'account',
            passwordField: 'password',
          });
    }
    // 这个方法会从你的 请求参数中 拿到用户名和密码，一定要传递请求参数！！！！
    async validate(account:string,password:string):Promise<any>{

        // console.log("local strategy ts enter",account,password);

        const user = await this.authService.validateUser(account,password);
        if(!user){
            throw new UnauthorizedException();
        }
        // console.log("local strategy ts leave",user);
        // 最终结果是在 在请求对象上创建user 属性 等价于res.user = user
        return user;
    }
}