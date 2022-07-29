import { Body, Controller, Get, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { GetUserAddress } from 'src/common/get-user-address.decorator';
import { GetCurrentUser } from 'src/common/get-user.decorator';
import { AuthRequest, AuthResponse } from './auth.dto';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';

@ApiTags('Login')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(LocalAuthGuard)
    @Post('login')
    async login(@Body() authRequest: AuthRequest, @Req() req) {
        return this.authService.login(req.user);
    }

    @ApiBearerAuth('access-token')
    @UseGuards(JwtAuthGuard)
    @Get('validity/:address')
    async validity(@Param('address') address: string, @Req() req): Promise<boolean> {
        return address.toLocaleLowerCase() === req.user.address.toLocaleLowerCase();
    }

    @ApiBearerAuth('refresh-token')
    @UseGuards(JwtRefreshGuard)
    @Get('refresh')
    async refreshToken(@Req() req): Promise<AuthResponse> {
        const user = req.user;
        return this.authService.refreshTokens(user.address, user.refreshToken);
    }
    
}
