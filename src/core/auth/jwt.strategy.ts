import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
// 注意这里是jwt策略
import { ExtractJwt, Strategy } from "passport-jwt";
import { jwtConstants } from "./constants";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration:false,
            secretOrKey:jwtConstants.secret,
        })
    }
    async validate(payload:any){
        return {
            account:payload.account,
            userId:payload.id
        }
    }
}