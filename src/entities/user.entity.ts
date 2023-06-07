import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { Post } from "./post.entity";

@Entity("user")
export class User{
    // 自增唯一主键
    @PrimaryGeneratedColumn()
    id:number;

    // 账户名类型
    @Column()
    account:string;

    // 密码
    @Column()
    password:string;

    // 用户名
    @Column()
    username:string;

    // 用户管理文章 多个文章对应一个用户
    @OneToMany(type=>Post,post=>post.user)
    posts:Post[];

    @Column()
    role:string;
}