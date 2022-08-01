import { ForbiddenException, Injectable, Req } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "src/user/user.entity";
import { AuthService } from "../auth.service";

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy, 'refresh-token') {
    constructor(
        private readonly configService: ConfigService,
        private readonly authService: AuthService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (reqeust) => {
                    return reqeust?.cookies?.Refresh;
                }
            ]),
            secretOrKey: configService.get<string>('jwt.refresh_secret'),
            passReqToCallback: true,
        });
    }

    async validate(@Req() req, payload: any) {
        const refreshToken = req.cookies?.Refresh;

        if(!refreshToken) throw new ForbiddenException('Refresh token malformed');

        return this.authService.validateRefreshToken(payload.address, refreshToken);
    }
}