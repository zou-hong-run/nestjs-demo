import { Module } from '@nestjs/common';
import { PostController } from './post.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Post } from 'src/entities/post.entity';
import { PostService } from './post.service';

@Module({
  imports:[
    TypeOrmModule.forFeature([Post])
  ],
  controllers: [PostController],
  providers: [PostService],
  exports:[PostService]
})
export class PostModule {}
