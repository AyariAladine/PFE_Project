import { IsNotEmpty } from 'class-validator';

export class ScanIdCardDto {
  @IsNotEmpty()
  image: Express.Multer.File;
}
