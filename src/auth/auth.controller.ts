import { Body, Controller, Get, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
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
    async login(
        @Body() authRequest: AuthRequest,
        @Req() req,
        @Res({ passthrough: true }) res) {

        const tokens =  await this.authService.login(req.user);
        res.cookie('Refresh', tokens.refreshToken, {
            httpOnly: true,
        });

        return tokens;
    }

    @ApiBearerAuth('access-token')
    @UseGuards(JwtAuthGuard)
    @Get('validity/:address')
    async validity(@Param('address') address: string, @Req() req): Promise<boolean> {
        return address.toLocaleLowerCase() === req.user.address.toLocaleLowerCase();
    }

    @UseGuards(JwtRefreshGuard)
    @Get('refresh')
    async refreshToken(@Req() req) {
        const user = req.user;
        return this.authService.refreshTokens(user.address, user.currentHashedRefreshToken);
    }
    
}
