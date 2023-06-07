import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable, map } from 'rxjs';

export interface Response<T> {
  data: T;
}

@Injectable()
export class HttpReqTransformInterceptor<T> 
  implements NestInterceptor<T,Response<T>> 
{
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    return next.handle()
    .pipe(map(data=>{
      return {
        data,
        code:200,
        msg:"",
        success:true
      }
    }))
  }
}
