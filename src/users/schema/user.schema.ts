import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema, Types } from 'mongoose';
import { UserRole } from './Role_enum';

@Schema({timestamps: true })
export class User extends Document  {
    @Prop({ required: true })
    name: string;
    @Prop({ required: true })
    lastName: string;
    @Prop({ required: true })
    identitynumber : string;
    @Prop({ required: true, unique: true })
    email: string;
    @Prop({ required: true })
    password: string
    @Prop({ required: true, enum: UserRole })
    role: UserRole;
    @Prop({required: true})
    phoneNumber: string;
    @Prop()
    profileImageUrl: string;
}
export const UserSchema = SchemaFactory.createForClass(User);