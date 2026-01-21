import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { EmailService } from 'src/config/email.service';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly emailService: EmailService
  ) {}

  async create(createUserDto: CreateUserDto) {
    const exist = await this.userModel.findOne({ email: createUserDto.email }).exec();
    if (exist) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const createdUser = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
    });

    const saved = await createdUser.save();

    try {
      await this.emailService.sendMail(
        saved.email,
        'Welcome to Our Platform',
        `<h2>Hello ${saved.name} ${saved.lastName},</h2><p>Welcome! Your account has been created successfully as <strong>${saved.role}</strong>.</p><p>Best regards,<br/>The Team</p>`
      );
    } catch (error) {
      console.error('Failed to send welcome email:', error);
    }

    const { password, ...result } = saved.toObject();
    return result;
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userModel.findOne({ email }).exec();
  }

  findAll() {
    return this.userModel.find().select('-password').exec();
  }

  async findOne(id: string) {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    const { password, ...result } = user.toObject();
    return result;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }

    if (updateUserDto.email) {
      const existing = await this.userModel
        .findOne({ email: updateUserDto.email, _id: { $ne: id } })
        .exec();
      if (existing) {
        throw new ConflictException('Email already in use');
      }
    }

    const updated = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();

    if (!updated) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    const { password, ...result } = updated.toObject();
    return result;
  }

  async remove(id: string) {
    const deleted = await this.userModel.findByIdAndDelete(id).exec();
    if (!deleted) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return {
      message: 'User deleted !',
      id: deleted._id,
    };
  }
  async updatePassword(userId: string, hashedPassword: string) {
  const updated = await this.userModel.findByIdAndUpdate(
    userId,
    { password: hashedPassword },
    { new: true }
  ).exec();

  if (!updated) {
    throw new NotFoundException(`User with ID ${userId} not found`);
  }

  return updated;
}
}
