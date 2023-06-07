import { Injectable } from "@nestjs/common";
import { createHash } from "crypto";

@Injectable()
export class CryptoUtil{
    constructor(){}
    /**
     * 加密登录密码
     * @param password 
     * @returns 
     */
    encryptPassword(password:string):string{
        return createHash("sha256").update(password).digest("hex")
    }
    checkPassword(password:string,encryptedPassword:any):boolean{
        const currentPass = this.encryptPassword(password);
        if(currentPass ===  encryptedPassword){
            return true;
        }
        return false;
    }

}