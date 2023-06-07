import { HttpException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { PostRegisterDto } from 'src/dto/post/post-register.dto';
import { Post } from 'src/entities/post.entity';
import { Repository } from 'typeorm';

@Injectable()
export class PostService {
    constructor(
        @InjectRepository(Post)
        private readonly postRepository:Repository<Post>
    ){}

    async create(createInput:PostRegisterDto|any):Promise<void>{
        await this.postRepository.save(createInput);
    }

    async remove(id:number):Promise<void>{
        const existing = await this.findOneById(id);
        // 服务器无法根据客户端请求的内容特性完成请求
        if(!existing) throw new HttpException(`删除失败，id为${id}的文章不存在`,406)
        await this.postRepository.remove(existing);
    }

    async update(id:number,updateInput:Post):Promise<void>{
        const existing = await this.findOneById(id);
        if(!existing) throw new HttpException(`更新失败，id为${id}的文章不存在`,406)
        updateInput.title && (existing.title = updateInput.title);
        updateInput.content && (existing.content = updateInput.content);
        await this.postRepository.save(existing);
    }

    /**
     * 根据用户id查询所有的文章
     * @param userId 
     * @returns 
     */
    async findAll(userId:number):Promise<Post[]>{
        return await this.postRepository.find({
            where:{
                user:{
                    id:userId
                }
            }
        })
    }


    async findOneById(id:number):Promise<Post>{
        return await this.postRepository.findOne({
            where:{
                id
            }
        })
    }


}
