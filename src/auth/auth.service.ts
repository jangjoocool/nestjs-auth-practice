import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
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

        if(user && user.signature === signature) {
            const { signature, ...result } = user;
            return result;
        }

        return null;
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

        const accessToken = this.jwtService.sign(payload);
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.refresh_token'),
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

        const isValidted = await compare(refreshToken, user.currentHashedRefreshToken);

        if(!isValidted) {
            throw new ForbiddenException('Access Denied');
        }
        
        const tokens = await this.getTokens(user.address, user.signature);
        await this.userSerivce.updateCurrentRefreshToken(tokens.refreshToken, user.address);

        return tokens;
    }
}
