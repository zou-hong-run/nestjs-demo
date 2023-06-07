import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class UserRegisterDto{

    @IsNotEmpty({
        message:'账户名称不能为空'
    })
    @ApiProperty({
        example:"admin",
        description:"账户名"
    })
    account:string;


    @IsNotEmpty({
        message:'用户密码不能为空'
    })
    @ApiProperty({
        example:"admin",
        description:"用户密码"
    })
    password:string;

    
    @IsNotEmpty({
        message:'用户昵称不能为空'
    })
    @ApiProperty({
        example:"系统管理员",
        description:"用户昵称"
    })
    username:string;

    @IsString()
    @ApiProperty({
        example:"admin",
        description:"用户角色"
    })
    role:string;
}