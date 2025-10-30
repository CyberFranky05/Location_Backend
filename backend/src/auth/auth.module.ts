import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { KeycloakService } from './keycloak.service';
import { DatabaseModule } from '../database/database.module';
import { GeolocationModule } from '../geolocation/geolocation.module';

@Module({
  imports: [DatabaseModule, GeolocationModule],
  controllers: [AuthController],
  providers: [KeycloakService],
  exports: [KeycloakService],
})
export class AuthModule {}
