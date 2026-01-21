import { IsNotEmpty, IsString, MinLength, Length } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  code: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  newPassword: string;
}