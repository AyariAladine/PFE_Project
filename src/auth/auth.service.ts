import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { EmailService } from '../config/email.service';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RefreshToken } from './schemas/refresh-token.schema';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
    @InjectModel(RefreshToken.name) private refreshTokenModel: Model<RefreshToken>,
  ) {}

  async signup(createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto);
    return {
      user,
      message: 'user created !',
    };
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    const payload = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = await this.generateRefreshToken(user._id.toString());
    try {
      await this.emailService.sendMail(
        user.email,
        'Login Notification',
        `<h2>Hello ${user.name},</h2><p>You have successfully logged in to your account.</p>`
      );
    } catch (error) {
      console.error('mail failed to send:', error);
    }
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        lastName: user.lastName,
        role: user.role,
      },
    };
  }

  async refresh(refreshToken: string) {
    const storedToken = await this.refreshTokenModel.findOne({ 
      token: refreshToken,
      isRevoked: false,
    }).exec();
    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (storedToken.expiresAt < new Date()) {
      await this.refreshTokenModel.findByIdAndDelete(storedToken._id);
      throw new UnauthorizedException('Refresh token expired');
    }
    const user = await this.usersService.findOne(storedToken.userId.toString());
    const payload = {
      userId: user._id,
      email: user.email,
      role: user.role,
    };
    const newAccessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const newRefreshToken = await this.generateRefreshToken(storedToken.userId.toString());
    await this.refreshTokenModel.findByIdAndUpdate(storedToken._id, {
      isRevoked: true,
      replacedByToken: newRefreshToken,
    });
    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    };
  }

  async logout(userId: string, refreshToken: string) {
    await this.refreshTokenModel.updateMany(
      { userId, token: refreshToken },
      { isRevoked: true }
    );

    return { message: 'Logged out !' };
  }

 

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await this.refreshTokenModel.create({
      userId,
      token,
      expiresAt,
      isRevoked: false,
    });

    return token;
  }

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials !');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return user;
  }

 async forgotPassword(email: string) {
  const user = await this.usersService.findByEmail(email);
  
  if (!user) {
    return { message: 'a verification code has been sent.' };
  }

  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();


  const resetToken = this.jwtService.sign(
    { userId: user._id.toString(), code: resetCode, type: 'password-reset' },
    { expiresIn: '15m' }
  );
  await this.refreshTokenModel.create({
    userId: user._id,
    token: resetToken,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), 
    isRevoked: false,
  });

  const emailHtml = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Password Reset Request</h2>
      <p>Hello ${user.name},</p>
      <p>You requested to reset your password. Use the verification code below:</p>
      <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px;">
        <h1 style="color: #007bff; letter-spacing: 5px; margin: 0; font-size: 36px;">${resetCode}</h1>
      </div>
      <p>This code will expire in <strong>15 minutes</strong>.</p>
      <p>If you didn't request this, please ignore this email.</p>
      <p style="color: #666; font-size: 12px; margin-top: 30px;">For security reasons, never share this code with anyone.</p>
    </div>
  `;

  try {
    await this.emailService.sendMail(user.email, 'Password Reset Code', emailHtml);
  } catch (error) {
    console.error('Failed to send reset email:', error);
    throw new BadRequestException('Failed to send reset email');
  }

  return { message: 'a verification code has been sent.' };
}

async resetPassword(code: string, newPassword: string) {
  const activeTokens = await this.refreshTokenModel.find({
    isRevoked: false,
    expiresAt: { $gt: new Date() },
  }).exec();

  let foundToken: { payload: any; tokenDoc: any } | null = null;

  for (const token of activeTokens) {
    try {
      const payload = this.jwtService.verify(token.token);
      if (payload.type === 'password-reset' && payload.code === code) {
        foundToken = { payload, tokenDoc: token };
        break;
      }
    } catch (error) {
      continue;
    }
  }

  if (!foundToken) {
    throw new BadRequestException('Invalid or expired verification code');
  }
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  

  await this.usersService.updatePassword(foundToken.payload.userId, hashedPassword);


  await this.refreshTokenModel.findByIdAndUpdate(foundToken.tokenDoc._id, {
    isRevoked: true,
  });


  const user = await this.usersService.findOne(foundToken.payload.userId);
  const emailHtml = `
    <h2>Password Reset Successful</h2>
    <p>Hello ${user.name},</p>
    <p>Your password has been successfully reset.</p>
    <p>If you didn't make this change, please contact support immediately.</p>
  `;

  try {
    await this.emailService.sendMail(user.email, 'Password Reset Successful', emailHtml);
  } catch (error) {
    console.error('Failed to send confirmation email:', error);
  }

  return { message: 'Password reset successful' };
}
}
