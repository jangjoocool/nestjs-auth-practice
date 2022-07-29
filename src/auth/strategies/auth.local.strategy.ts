import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { AuthService } from "../auth.service";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
    constructor(private authService: AuthService) {
        super({
            usernameField: 'address',
            passwordField: 'signature',
        });
    }

   async validate(address: string, signature: string): Promise<any> {
        const user = await this.authService.validateUser(address, signature);
        if(!user) {
            throw new UnauthorizedException();
        }
        return user;
   }
}