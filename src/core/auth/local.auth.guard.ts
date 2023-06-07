import { ExecutionContext, Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class LocalAuthGuard extends AuthGuard("local"){
    handleRequest<TUser = any>(err: any, user: any, info: any, context: ExecutionContext, status?: any): TUser {
        const request = context.switchToHttp().getRequest();
        const {username,password} =request.body;
        // console.log(username,password,user);
        return user;
    }
}