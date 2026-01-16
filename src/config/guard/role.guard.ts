import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { ROLES_KEY } from 'src/config/decorator/role.decorators';
import { UserRole } from 'src/users/schema/Role_enum';


@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      this.logger.warn('No authorization header found');
      throw new UnauthorizedException('No authorization token provided');
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded = this.jwtService.verify(token);
      
      request.user = decoded;

      this.logger.debug(`User role: ${decoded.role}, Required roles: ${requiredRoles}`);
      
      const hasRole = requiredRoles.includes(decoded.role);
      
      if (!hasRole) {
        this.logger.warn(`Access denied for user ${decoded.userId} with role ${decoded.role}`);
        throw new UnauthorizedException(`User role ${decoded.role} is not authorized to access this resource`);
      }

      return true;
    } catch (error) {
      this.logger.error(`Authentication error: ${error.message}`);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}