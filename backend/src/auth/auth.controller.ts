import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  HttpException,
  HttpStatus,
  Query,
  Headers,
} from '@nestjs/common';
import type { Request } from 'express';
import { KeycloakService } from './keycloak.service';
import { DatabaseService } from '../database/database.service';
import { GeolocationService } from '../geolocation/geolocation.service';
import { SignUpDto, SignInDto, RefreshTokenDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly keycloakService: KeycloakService,
    private readonly databaseService: DatabaseService,
    private readonly geolocationService: GeolocationService,
  ) {}

  @Post('signup')
  async signUp(@Body() signUpDto: SignUpDto, @Req() request: Request) {
    try {
      // Extract IP and get location
      const ipAddress = this.geolocationService.extractIPFromRequest(request);
      const locationData = await this.geolocationService.getLocationFromIP(ipAddress);
      const userAgent = request.headers['user-agent'] || '';
      const { browser, device, os } = this.geolocationService.parseUserAgent(userAgent);

      // Split name into first and last name
      const nameParts = signUpDto.name.trim().split(' ');
      const firstName = nameParts[0];
      const lastName = nameParts.slice(1).join(' ') || nameParts[0];

      // Check if user already exists in database
      const existingUser = await this.databaseService.getUserByEmail(signUpDto.email);
      if (existingUser) {
        throw new HttpException('User already exists', HttpStatus.CONFLICT);
      }

      // Create user in Keycloak
      const keycloakUser = await this.keycloakService.createUser({
        username: signUpDto.email,
        email: signUpDto.email,
        firstName,
        lastName,
        password: signUpDto.password,
      });

      // Save user to Supabase
      const user = await this.databaseService.createUser({
        keycloak_id: keycloakUser.id,
        name: signUpDto.name,
        email: signUpDto.email,
      });

      // Log the sign-up as a successful sign-in attempt
      await this.databaseService.createSignInAttempt({
        user_id: user.id,
        email: signUpDto.email,
        ip_address: ipAddress,
        country: locationData.country,
        city: locationData.city,
        region: locationData.region,
        latitude: locationData.latitude,
        longitude: locationData.longitude,
        timezone: locationData.timezone,
        isp: locationData.isp,
        user_agent: userAgent,
        browser,
        device,
        os,
        success: true,
      });

      return {
        message: 'User created successfully',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        error.message || 'Failed to create user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('signin')
  async signIn(@Body() signInDto: SignInDto, @Req() request: Request) {
    console.log('🔓 Sign-in attempt for:', signInDto.email);
    
    // Extract IP and location data
    const ipAddress = this.geolocationService.extractIPFromRequest(request);
    const locationData = await this.geolocationService.getLocationFromIP(ipAddress);
    const userAgent = request.headers['user-agent'] || '';
    const { browser, device, os } = this.geolocationService.parseUserAgent(userAgent);

    try {
      // Authenticate with Keycloak
      const tokens = await this.keycloakService.authenticate(
        signInDto.email,
        signInDto.password,
      );
      console.log('✅ Keycloak authentication successful');

      // Get user info from Keycloak
      console.log('📋 Getting user info from Keycloak...');
      const userInfo = await this.keycloakService.getUserInfo(tokens.access_token);
      console.log('User info:', { sub: userInfo.sub, email: userInfo.email });

      // Get or create user in database
      console.log('🔍 Looking up user in database...');
      let user = await this.databaseService.getUserByKeycloakId(userInfo.sub);
      
      if (!user) {
        console.log('⚠️ User not found in database, creating...');
        // User exists in Keycloak but not in our database (shouldn't happen but handle it)
        user = await this.databaseService.createUser({
          keycloak_id: userInfo.sub,
          name: userInfo.name || userInfo.preferred_username,
          email: userInfo.email,
        });
        console.log('✅ User created in database');
      } else {
        console.log('✅ User found in database:', user.id);
      }

      // Log successful sign-in attempt
      console.log('📝 Logging sign-in attempt...');
      await this.databaseService.createSignInAttempt({
        user_id: user.id,
        email: signInDto.email,
        ip_address: ipAddress,
        country: locationData.country,
        city: locationData.city,
        region: locationData.region,
        latitude: locationData.latitude,
        longitude: locationData.longitude,
        timezone: locationData.timezone,
        isp: locationData.isp,
        user_agent: userAgent,
        browser,
        device,
        os,
        success: true,
      });
      console.log('✅ Sign-in attempt logged');

      console.log('✅ Sign-in complete, returning tokens');
      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      };
    } catch (error) {
      console.error('❌ Sign-in failed:', error.message);
      console.error('Error stack:', error.stack);
      
      // Log failed sign-in attempt
      await this.databaseService.createSignInAttempt({
        email: signInDto.email,
        ip_address: ipAddress,
        country: locationData.country,
        city: locationData.city,
        region: locationData.region,
        latitude: locationData.latitude,
        longitude: locationData.longitude,
        timezone: locationData.timezone,
        isp: locationData.isp,
        user_agent: userAgent,
        browser,
        device,
        os,
        success: false,
        failure_reason: error.message || 'Invalid credentials',
      });

      throw new HttpException(
        error.message || 'Authentication failed',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  @Post('refresh')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    try {
      const tokens = await this.keycloakService.refreshToken(refreshTokenDto.refresh_token);
      
      return {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
      };
    } catch (error) {
      throw new HttpException('Token refresh failed', HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('logout')
  async logout(@Body() refreshTokenDto: RefreshTokenDto) {
    try {
      await this.keycloakService.logout(refreshTokenDto.refresh_token);
      return { message: 'Logged out successfully' };
    } catch (error) {
      // Even if logout fails, return success
      return { message: 'Logged out successfully' };
    }
  }

  @Get('signin-attempts')
  async getSignInAttempts(
    @Headers('authorization') authorization: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ) {
    try {
      // Extract token from Authorization header
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException('Missing or invalid authorization header', HttpStatus.UNAUTHORIZED);
      }

      const accessToken = authorization.substring(7);

      // Verify token and get user info
      const userInfo = await this.keycloakService.getUserInfo(accessToken);

      // Get user from database
      const user = await this.databaseService.getUserByKeycloakId(userInfo.sub);
      
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Get sign-in attempts
      const attempts = await this.databaseService.getSignInAttemptsByUserId(
        user.id,
        limit ? parseInt(limit) : 50,
        offset ? parseInt(offset) : 0,
      );

      return {
        attempts,
        total: attempts.length,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Failed to retrieve sign-in attempts',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('profile')
  async getProfile(@Headers('authorization') authorization: string) {
    try {
      if (!authorization || !authorization.startsWith('Bearer ')) {
        throw new HttpException('Missing or invalid authorization header', HttpStatus.UNAUTHORIZED);
      }

      const accessToken = authorization.substring(7);

      // Get user info from Keycloak
      const userInfo = await this.keycloakService.getUserInfo(accessToken);

      // Get user from database
      const user = await this.databaseService.getUserByKeycloakId(userInfo.sub);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          created_at: user.created_at,
        },
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException('Failed to get profile', HttpStatus.UNAUTHORIZED);
    }
  }
}
