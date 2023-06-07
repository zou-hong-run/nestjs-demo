import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AllExceptionFilter } from './core/filters/all-exception.filter';
import { HttpReqTransformInterceptor } from './core/interceptors/http-req.interceptor';

declare const module:any;


async function bootstrap() {
  // 使用express作为默认配置
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  
  // 全局异常过滤
  app.useGlobalFilters(new AllExceptionFilter())
  // 全局拦截器
  app.useGlobalInterceptors(new HttpReqTransformInterceptor())



  // swagger配置
  const options = new DocumentBuilder()
    .setTitle("red润的入门小项目")
    .setDescription("一个初级练习项目")
    .addBearerAuth()
    .setVersion("1.0")
    .build();
  
  const documents = SwaggerModule.createDocument(app,options);
  SwaggerModule.setup("api",app,documents);




  await app.listen(3000);

  // 热重载
  if (module.hot) {
    module.hot.accept();
    module.hot.dispose(() => app.close());
  }

}
bootstrap();
