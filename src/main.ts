import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  const swaggerOptions =  new DocumentBuilder()
    .setTitle('Practice NestJS API')
    .setDescription('NestJS Study API description')
    .setVersion('1.0.0')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerOptions);
  SwaggerModule.setup('api-docs', app, document);

  const port = configService.get<number>('server.port');
  await app.listen(port);
}
bootstrap();