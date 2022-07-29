import { ForbiddenException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RegistRequest, RegistResponse } from './user.dto';
import { User } from './user.entity';
import { v4 as uuidv4 } from 'uuid';
import { compare, hash } from 'bcrypt';

@Injectable()
export class UserService {
    constructor(@InjectRepository(User) private readonly userRepository: Repository<User>) {}

    async findByAddress(address: string): Promise<User> {
        return this.userRepository.findOneBy({
            address: address
        });
    }

    async registration(registRequest: RegistRequest): Promise<RegistResponse> {
        const user = new User();
        user.address = registRequest.address;
        user.nonce = uuidv4();
        user.signature = null;
        user.issDate = new Date();
        user.authDate = null;

        this.userRepository.upsert(user, ["address"]);

        const response: RegistResponse = {
            nonce: user.nonce,
        }

        return response;
    }

    async updateAuthDate(address: string) {
        const newAuthDate = new Date();
        this.userRepository.update(address, {
            authDate: newAuthDate,
        });
    }

    async updateCurrentRefreshToken(refreshToken: string, address: string): Promise<void> {
        const currentHashedRefreshToken = await hash(refreshToken, 10);
        await this.userRepository.update(address, {currentHashedRefreshToken});
    }
    
}
