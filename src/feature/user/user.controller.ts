import { Body, Controller, Delete, Get, Param, Post, Put, Req, Request, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiProperty, ApiQuery, ApiTags } from '@nestjs/swagger';
import { Public } from 'src/common/decorators/public.decorator';
import { AuthService } from 'src/core/auth/auth.service';
import { UserService } from './user.service';
import { UserRegisterDto } from 'src/dto/user/user-register.dto';
import { User } from 'src/entities/user.entity';

@ApiTags('user')
// 这个很重要，没有他，swagger请求头不会带token发送请求
@ApiBearerAuth()
@Controller('user')
export class UserController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ) {}

  @ApiOperation({summary:"测试token是否通过获取用户信息"})
  @Get("profile")
  getProfile(@Req() req){
    // console.log("profile");
    // 获取到用户的token中的内容
    return req.user
  }

  @Public()
  @ApiOperation({summary:"注册用户(不用携带token)"})
  @ApiBody({type:UserRegisterDto,description:"输入用户的各种信息"})
  @Post("register")
  async register(@Body() user:UserRegisterDto):Promise<any>{
    await this.userService.register(user);
    return "注册成功"
  }


  @ApiOperation({summary:"通过id删除用户"})
  @ApiParam({name:'id',required:true,description:"删除用户的id"})
  @Delete(":id")
  async remove(@Param() id:number):Promise<any>{
    await this.userService.remove(id);
    return "删除成功"
  }

  @ApiOperation({summary:"通过用户id更新用户信息"})
  @ApiParam({name:"id",required:true,description:"更新用户的id"})
  @ApiBody({type:UserRegisterDto,description:"输入更改的信息"})
  @Put(":id")
  async update(@Param()id:number,@Body() updateInput:UserRegisterDto):Promise<any>{
    const data = await this.userService.update(id,updateInput);
    return data;
  }


  @ApiOperation({summary:"查询单个用户和用户关联的文章"})
  @ApiParam({name:"id",required:true,description:"想要查询的id"})
  @Get(":id")
  async findOne(@Param() id:number):Promise<any>{
    const data = await this.userService.findOneWithPostsById(id);
    return data
  }

  @ApiOperation({summary:"查询所有用户"})
  @Get()
  async findAll():Promise<any>{
    const data = await this.userService.findAll();
    return data
  }





}
