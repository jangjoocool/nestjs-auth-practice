import { ApiProperty } from "@nestjs/swagger";
import { IsString, Matches } from "class-validator";

export class AuthRequest {
    @ApiProperty({ description: '지갑 주소', required: true})
    @IsString()
    @Matches(/0x[a-fA-F0-9]{40}/)
    address: string;
    
    @ApiProperty({ description: '서명 데이터', required: true})
    signature: string;    
}

export class AuthResponse {
    @ApiProperty({ description: 'Access Token', required: true})
    accessToken: string;

    @ApiProperty({ description: 'Refresh Token', required: true})
    refreshToken: string;
}