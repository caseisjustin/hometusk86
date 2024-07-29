import { ConflictException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private mailerService: MailerService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && await bcrypt.compare(pass, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async register(username: string, email: string, pass: string): Promise<Partial<User | {message: string}>> {
    const existingUser = await this.usersService.findOne(username);
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }
    const existingEmail = await this.usersService.findByEmail(email);
    if (existingEmail) {
      throw new ConflictException('Email already exists');
    }
    const hashedPassword = await bcrypt.hash(pass, 10);
    const emailVerificationToken = this.jwtService.sign({ email }, { expiresIn: '1h' });
    const user = await this.usersService.create({
      username,
      email,
      password: hashedPassword,
      emailVerificationToken,
      emailVerificationTokenExpires: new Date(Date.now() + 60 * 60 * 1000),
    });

    await this.sendVerificationEmail(email, emailVerificationToken);
  
    return {message: "You have successfuly signed up", username: user.username, email: user.email};
  }

  async sendVerificationEmail(email: string, token: string) {
    const url = `http://localhost:3000/auth/verify-email?token=${token}`;
    await this.mailerService.sendMail({
      to: email,
      subject: 'Email Verification',
      text: `Please verify your email by clicking the following link: ${url}`,
    });
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async resetPassword(email: string, oldPassword: string, newPassword: string, confirmNewPassword: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new Error('User not found');
    }
    if ( !(await bcrypt.compare(oldPassword, user.password))) {
      throw new Error("Invalid Password");
    }
    if( newPassword !== confirmNewPassword){
      throw new Error("Passwords not matched.")
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.usersService.updatePassword(user.id, hashedPassword);
  }

  async forgotPassword(email: string): Promise<string> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new Error('User not found');
    }
    const token = this.jwtService.sign({ email }, { expiresIn: '1h' });
    // Send email logic here with the token
    return token;
  }

  async verifyAndConfirmEmail(token: string): Promise<void> {
    const { email } = this.jwtService.verify(token);
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new ConflictException('User not found');
    }
    if (user.emailVerificationToken !== token) {
      throw new ConflictException('Invalid or expired verification token');
    }
    if (new Date() > user.emailVerificationTokenExpires) {
      throw new ConflictException('Verification token expired');
    }
    await this.usersService.confirmEmail(user.id);
  }

  async renewTokens(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
      refresh_token: this.jwtService.sign(payload, { expiresIn: '7d' }),
    };
  }
}
