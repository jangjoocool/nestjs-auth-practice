import { Exclude } from "class-transformer";
import { Column, Entity, PrimaryColumn } from "typeorm";

@Entity('User')
export class User {
    @PrimaryColumn({
        length: 42,
    })
    address: string

    @Column({
        length: 36,
    })
    nonce: string

    @Column({
        nullable: true
    })
    signature: string

    @Column({
        type: "timestamp",
        default: () => "CURRENT_TIMESTAMP"
    })
    regDate: Date

    @Column({
        type: "timestamp",
        nullable: true,
    })
    issDate: Date

    @Column({
        type: "timestamp",
        nullable: true
    })
    authDate: Date

    @Column({ nullable: true })
    @Exclude()
    currentHashedRefreshToken?: string;

}