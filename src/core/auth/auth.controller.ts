import { Controller, Get, Post, Request, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from "@nestjs/swagger";
import { AuthService } from "./auth.service";
import { Public } from "src/common/decorators/public.decorator";
import { AuthGuard } from "@nestjs/passport";
import { ReqLoginDTO } from "src/dto/req-login.dto";


@ApiTags('登录权限')
// 这个很重要，没有他，swagger请求头不会带token发送请求
@ApiBearerAuth()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({summary:"用户登录拿到token"})
  @Public()// 不用jwt校验的装饰器
  @UseGuards(AuthGuard('local'))
  // @UseGuards(LocalAuthGuard) 
  @Post("login")
  @ApiBody({
    type:ReqLoginDTO,
    description:"请求体参数"
  })
  async login(@Request() req){
    // console.log("gggggggggS",req.user);
    return this.authService.login(req.user);
  }

  @ApiOperation({summary:"测试token是否通过获取用户信息"})
  @Get("profile")
  getProfile(@Request()req){
    // console.log("profile");
    // 获取到用户的token中的内容
    return req.user
  }
}
