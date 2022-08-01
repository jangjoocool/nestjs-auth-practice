import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { doesNotMatch } from 'assert';
import { compare } from 'bcrypt';
import { User } from 'src/user/user.entity';
import { UserService } from 'src/user/user.service';
import { AuthResponse } from './auth.dto';

@Injectable()
export class AuthService {
    constructor(
        private configService: ConfigService,
        private userSerivce: UserService,
        private jwtService: JwtService,
    ) {}

    async validateUser(address: string, signature: string): Promise<any> {
        const user = await this.userSerivce.findByAddress(address);
        if(!user || user.signature !== signature) {
            return null;
        } else{
            return user;
        }
    }

    async login(user: any): Promise<AuthResponse> {
        const payload = {
            address: user.address,
            signature: user.signature,
        };
        const tokens = await this.getTokens(user.address, user.signature);
        
        await this.userSerivce.updateAuthDate(user.address);
        await this.userSerivce.updateCurrentRefreshToken(tokens.refreshToken, user.address);
        
        return tokens;
    }

    async getTokens(address: string, signature: string): Promise<AuthResponse> {
        const payload = {
            address: address,
            signature: signature,
        }

        const accessToken = await this.jwtService.signAsync(payload);
        const refreshToken = await this.jwtService.signAsync(payload, {
            secret: this.configService.get<string>('jwt.refresh_secret'),
            expiresIn: this.configService.get<string>('jwt.refresh_expiresIn'),
        });

        return {
            accessToken: accessToken,
            refreshToken: refreshToken,
        }
    }

    async refreshTokens(address: string, refreshToken: string): Promise<AuthResponse> {
        const user = await this.userSerivce.findByAddress(address);
        if(!user || !user.currentHashedRefreshToken) {
            throw new ForbiddenException('Access Denied');
        }
      
        const tokens = await this.getTokens(user.address, user.signature);
        await this.userSerivce.updateCurrentRefreshToken(tokens.refreshToken, user.address);

        return tokens;
    }

    async validateRefreshToken(address: string, refreshToken: string): Promise<User> {
        const user = await this.userSerivce.findByAddress(address);
        if(!user || !user.currentHashedRefreshToken) {
            throw new ForbiddenException('Access Denied');
        }

        const isValidted = await compare(refreshToken, user.currentHashedRefreshToken);

        if(!isValidted) {
            throw new ForbiddenException('Access Denied');
        } else {
            return user
        }
      
    }
}
