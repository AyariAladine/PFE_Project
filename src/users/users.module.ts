import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { OcrService } from './ocr.service';
import { UsersController } from './users.controller';
import { EmailModule } from 'src/config/email.module';
import { User, UserSchema } from './schema/user.schema';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
    imports: [EmailModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }])],
  controllers: [UsersController],
  providers: [UsersService, OcrService],
  exports: [UsersService],
})
export class UsersModule {}
