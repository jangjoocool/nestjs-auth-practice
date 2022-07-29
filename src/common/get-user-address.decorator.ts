import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const GetUserAddress = createParamDecorator(
    (_: undefined, context: ExecutionContext): string => {
        const request = context.switchToHttp().getRequest();
        console.log(request.user);
        const user = request.user;
        return user.address;
    }
)