import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class PostRegisterDto{

    @IsNotEmpty({
        message:'文章标题不能为空'
    })
    @ApiProperty({
        example:"title",
        description:"标题名"
    })
    title:string;


    @IsNotEmpty({
        message:'内容不能为空'
    })
    @ApiProperty({
        example:"content",
        description:"用户内容"
    })
    content:string;
}