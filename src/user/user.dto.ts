import { ApiProperty } from "@nestjs/swagger";
import { IsString, Matches } from "class-validator";

export class RegistRequest {
    @ApiProperty({ description: '주소', required: true})
    @IsString()
    @Matches(/0x[a-fA-F0-9]{40}/)
    address: string;
}

export class RegistResponse {
    @ApiProperty({ description: '서명 데이터를 위한 임의의 넌스', required: true })
    nonce: string;
}