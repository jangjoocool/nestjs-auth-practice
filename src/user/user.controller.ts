import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RegistRequest } from './user.dto';
import { User } from './user.entity';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @ApiTags('Login')
    @Post()
    async registration(@Body() registRequest: RegistRequest) {
        return this.userService.registration(registRequest);
    }

    @ApiTags('Info')
    @ApiBearerAuth('access-token')
    @UseGuards(JwtAuthGuard)
    @Get(':address')
    async findOne(@Param('address') address: string): Promise<User> {
        return this.userService.findByAddress(address);
    }
}
