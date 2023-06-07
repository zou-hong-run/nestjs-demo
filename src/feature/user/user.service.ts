import { HttpException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CryptoUtil } from 'src/common/utils/crypto.util';
import { UserRegisterDto } from 'src/dto/user/user-register.dto';
import { User } from 'src/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
    async onModuleInit() {
        if (await this.findOneByAccount('admin')) return;
        // 初始化系统管理员
        const admin = this.userRepository.create({
            account:'admin',
            password:this.cryptoUtil.encryptPassword("admin"),
            username:"系统管理员",
            role:"admin"
        });
        await this.userRepository.save(admin);
    }
    // 注入 一个操作数据表，一个加密密码
    constructor(
        @InjectRepository(User)
        private readonly userRepository:Repository<User>,
        private readonly cryptoUtil:CryptoUtil,
    ){}

    /**
     * 通过登录账号查询用户
     *
     * @param account 登录账号
     */
    async findOneByAccount(account: string): Promise<User> {
        const user = await this.userRepository.findOne({
            where:{
                account
            }
        });
        return user
    }
    async findOne(account:string):Promise<User|undefined>{
        // console.log("user service ts findone enter",account);
        const user = await this.userRepository.findOne({
            where:{
                account
            }
        });
        
        // console.log("user service ts findone leave",user);
        return user;
    }

    /**
     * 创建用户
     * @param user 
     */
    async register(user:UserRegisterDto):Promise<void>{
        const existing = await this.findOneByAccount(user.account);
        // 406 Not Acceptable
        if(existing)throw new HttpException("账户已经存在了",406);
        user.password = this.cryptoUtil.encryptPassword(user.password);
        await this.userRepository.save(this.userRepository.create(user));
    }

    async remove(id:number):Promise<void>{
        const existing = await this.userRepository.findOne({
            where:{id}
        });
        if(!existing) throw new HttpException(`删除用户Id为${id}的用户不存在`,406)
        await this.userRepository.remove(existing);
    }

    async update(id:number,updatInput:UserRegisterDto){
        const existing = await this.userRepository.findOne({
            where:{
                id
            }
        });
        if(!existing) throw new HttpException(`更新用户Id为${id}的用户不存在`,406)
        if(updatInput.account) existing.account = updatInput.account;
        if(updatInput.username) existing.username = updatInput.username;
        await this.userRepository.save(existing)
    }

    async findOneWithPostsById(id:number):Promise<User>{
        return await this.userRepository.findOne({
            where:{
                id
            },
            relations:['posts']
        })
    }
    async findAll():Promise<User[]>{
        return await this.userRepository.find();
    }


}
