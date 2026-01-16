import { Injectable, UnauthorizedException } from '@nestjs/common';
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
}
