import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { LoginDto, SignupDto } from '../auth/dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async signup(dto: SignupDto) {
    // Check if user exists
    const userExists = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (userExists) {
      throw new ConflictException('Email already exists');
    }

    // Hash password
    const hash = await bcrypt.hash(dto.password, 10);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hash,
        name: dto.name,
        role: dto.role || 'STUDENT',
      },
    });

    // Generate token
    const token = await this.signToken(user.id, user.email);

    return {
      message: 'User created successfully',
      token,
    };
  }

  async login(dto: LoginDto) {
    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Compare password
    const match = await bcrypt.compare(dto.password, user.password);

    if (!match) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate token
    const token = await this.signToken(user.id, user.email);

    return {
      message: 'Logged in successfully',
      token,
    };
  }

  private async signToken(userId: string, email: string) {
    const payload = {
      sub: userId,
      email,
    };

    return this.jwt.sign(payload);
  }
}
