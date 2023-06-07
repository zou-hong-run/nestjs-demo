import { Body, Controller, Delete, Get, Param, Post, Put, Req } from '@nestjs/common';
import { PostService } from './post.service';
import { Request } from 'express';
import { Post as PostEntity } from 'src/entities/post.entity';
import { User } from 'src/entities/user.entity';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { PostRegisterDto } from 'src/dto/post/post-register.dto';
import { Public } from 'src/common/decorators/public.decorator';

@ApiTags("post")
@ApiBearerAuth()
@Controller('post')
export class PostController {
  constructor(private readonly postService: PostService) {}

  
  @ApiOperation({summary:"创建文章"})
  @ApiBody({type:PostRegisterDto,description:"输入创建的用户信息"})
  @Post()
  async createPost(@Req() req:Request,@Body() createInput:PostRegisterDto|any ):Promise<any>{
    createInput.userId = req.user as User;
    console.log(createInput);
    await this.postService.create(createInput);
    return "创建成功"
  }

  @ApiOperation({summary:"删除文章"})
  @Delete(":id")
  async remove(@Param() id:number):Promise<any>{
    await this.postService.remove(id);
    return "删除文章成功"
  }


  @ApiOperation({summary:"更新文章"})
  @Put(":id")
  async update(@Param() id:number,@Body() updateInpt:PostEntity):Promise<any>{
    await this.postService.update(id,updateInpt);
    return "更新成功";
  }

  @ApiOperation({summary:"根据用户的信息查询所有文章"})
  @Get()
  async findAll(@Req() req:Request):Promise<any>{
    const data = await this.postService.findAll((req.user as User).id);
    return data;// 查询该用户的所有文章
  }

  
  @ApiOperation({summary:"查询单个帖子"})
  @Get(":id")
  async findOne(@Param() id:number):Promise<any>{
    const data = await this.postService.findOneById(id);
    return data;// 查询单个文章
  }


}
