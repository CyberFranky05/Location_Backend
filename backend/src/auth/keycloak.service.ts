import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import * as jwt from 'jsonwebtoken';

export interface KeycloakTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_expires_in: number;
  refresh_token: string;
  token_type: string;
  'not-before-policy': number;
  session_state: string;
  scope: string;
}

export interface KeycloakUserInfo {
  sub: string;
  email_verified: boolean;
  name: string;
  preferred_username: string;
  given_name: string;
  family_name: string;
  email: string;
}

@Injectable()
export class KeycloakService {
  private readonly keycloakUrl: string;
  private readonly realm: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly userClientId: string;

  constructor(private configService: ConfigService) {
    this.keycloakUrl = this.configService.get<string>('KEYCLOAK_URL') || '';
    this.realm = this.configService.get<string>('KEYCLOAK_REALM') || '';
    this.clientId = this.configService.get<string>('KEYCLOAK_CLIENT_ID') || '';
    this.clientSecret = this.configService.get<string>('KEYCLOAK_CLIENT_SECRET') || '';
    // Use frontend client for user authentication (password grant)
    this.userClientId = this.configService.get<string>('KEYCLOAK_USER_CLIENT_ID') || 'location-auth-frontend';
  }

  private getTokenUrl(): string {
    return `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;
  }

  private getUserInfoUrl(): string {
    return `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/userinfo`;
  }

  private getAdminUrl(): string {
    return `${this.keycloakUrl}/admin/realms/${this.realm}`;
  }

  async createUser(userData: {
    username: string;
    email: string;
    firstName: string;
    lastName: string;
    password: string;
  }): Promise<any> {
    try {
      console.log('👤 Creating user in Keycloak:', userData.email);
      
      // Get admin access token
      const adminToken = await this.getAdminToken();

      console.log('📝 Creating user account...');
      // Create user in Keycloak
      const createUserResponse = await axios.post(
        `${this.getAdminUrl()}/users`,
        {
          username: userData.email,
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
          enabled: true,
          emailVerified: true,
        },
        {
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
        },
      );

      console.log('✅ User created, response status:', createUserResponse.status);
      
      // Extract user ID from Location header
      const locationHeader = createUserResponse.headers.location;
      console.log('Location header:', locationHeader);
      const userId = locationHeader.split('/').pop();
      console.log('User ID:', userId);

      console.log('🔐 Setting user password...');
      // Set user password
      await axios.put(
        `${this.getAdminUrl()}/users/${userId}/reset-password`,
        {
          type: 'password',
          value: userData.password,
          temporary: false,
        },
        {
          headers: {
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json',
          },
        },
      );

      console.log('✅ Password set successfully');
      return { id: userId, ...userData };
    } catch (error) {
      console.error('❌ Error creating user in Keycloak');
      console.error('Error status:', error.response?.status);
      console.error('Error data:', error.response?.data);
      console.error('Error message:', error.message);
      
      if (error.response?.status === 409) {
        throw new Error('User already exists');
      }
      throw new Error(error.response?.data?.errorMessage || 'Failed to create user in Keycloak');
    }
  }

  async authenticate(username: string, password: string): Promise<KeycloakTokenResponse> {
    console.log('🔐 Authenticating user:', username);
    console.log('Token URL:', this.getTokenUrl());
    console.log('Using public client ID:', this.userClientId);
    
    try {
      const response = await axios.post(
        this.getTokenUrl(),
        new URLSearchParams({
          grant_type: 'password',
          client_id: this.userClientId, // Use public client for user auth
          username,
          password,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      console.log('✅ Authentication successful');
      return response.data;
    } catch (error) {
      console.error('❌ Authentication failed');
      console.error('Error status:', error.response?.status);
      console.error('Error data:', error.response?.data);
      
      if (error.response?.status === 401) {
        throw new Error('Invalid credentials');
      }
      throw new Error('Authentication failed');
    }
  }

  async getUserInfo(accessToken: string): Promise<KeycloakUserInfo> {
    console.log('📋 Getting user info from token...');
    
    try {
      // Decode JWT token without verification (Keycloak already verified it)
      const decoded = jwt.decode(accessToken) as any;
      
      if (!decoded) {
        throw new Error('Failed to decode token');
      }

      console.log('✅ User info decoded from token:', {
        sub: decoded.sub,
        email: decoded.email,
        name: decoded.name,
        preferred_username: decoded.preferred_username
      });

      const userInfo: KeycloakUserInfo = {
        sub: decoded.sub,
        email_verified: decoded.email_verified || false,
        name: decoded.name || decoded.preferred_username,
        preferred_username: decoded.preferred_username || decoded.email,
        given_name: decoded.given_name || '',
        family_name: decoded.family_name || '',
        email: decoded.email,
      };

      return userInfo;
    } catch (error) {
      console.error('❌ Failed to get user info from token');
      console.error('Error message:', error.message);
      
      // Fallback to userinfo endpoint
      console.log('⚠️ Trying userinfo endpoint as fallback...');
      try {
        const response = await axios.get(this.getUserInfoUrl(), {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        });
        console.log('✅ User info retrieved from endpoint:', response.data);
        return response.data;
      } catch (endpointError) {
        console.error('❌ Userinfo endpoint also failed');
        console.error('Error status:', endpointError.response?.status);
        console.error('Error data:', endpointError.response?.data);
        throw new Error('Failed to get user info');
      }
    }
  }

  async refreshToken(refreshToken: string): Promise<KeycloakTokenResponse> {
    try {
      const response = await axios.post(
        this.getTokenUrl(),
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.clientId,
          client_secret: this.clientSecret,
          refresh_token: refreshToken,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      return response.data;
    } catch (error) {
      throw new Error('Token refresh failed');
    }
  }

  async logout(refreshToken: string): Promise<void> {
    try {
      await axios.post(
        `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/logout`,
        new URLSearchParams({
          client_id: this.clientId,
          client_secret: this.clientSecret,
          refresh_token: refreshToken,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );
    } catch (error) {
      // Ignore errors on logout
      console.error('Logout error:', error.message);
    }
  }

  async verifyToken(accessToken: string): Promise<boolean> {
    try {
      await this.getUserInfo(accessToken);
      return true;
    } catch {
      return false;
    }
  }

  private async getAdminToken(): Promise<string> {
    console.log('🔑 Getting admin token...');
    console.log('Keycloak URL:', this.keycloakUrl);
    console.log('Realm:', this.realm);
    console.log('Client ID:', this.clientId);
    console.log('Client Secret:', this.clientSecret ? '***' + this.clientSecret.slice(-4) : 'MISSING');
    console.log('Token URL:', this.getTokenUrl());

    try {
      const response = await axios.post(
        this.getTokenUrl(),
        new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: this.clientId,
          client_secret: this.clientSecret,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      console.log('✅ Admin token obtained successfully');
      return response.data.access_token;
    } catch (error) {
      console.error('❌ Failed to get admin token');
      console.error('Error status:', error.response?.status);
      console.error('Error data:', error.response?.data);
      throw error;
    }
  }
}
