import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

@Injectable()
export class DatabaseService implements OnModuleInit {
  private supabase: SupabaseClient;

  constructor(private configService: ConfigService) {}

  onModuleInit() {
    const supabaseUrl = this.configService.get<string>('SUPABASE_URL');
    const supabaseKey = this.configService.get<string>('SUPABASE_SERVICE_ROLE_KEY');

    if (!supabaseUrl || !supabaseKey) {
      throw new Error('Supabase credentials are missing');
    }

    this.supabase = createClient(supabaseUrl, supabaseKey);
    console.log('✅ Supabase client initialized');
  }

  getClient(): SupabaseClient {
    return this.supabase;
  }

  // User operations
  async createUser(data: {
    keycloak_id: string;
    name: string;
    email: string;
  }) {
    const { data: user, error } = await this.supabase
      .from('users')
      .insert(data)
      .select()
      .single();

    if (error) throw error;
    return user;
  }

  async getUserByEmail(email: string) {
    const { data, error } = await this.supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error && error.code !== 'PGRST116') throw error; // PGRST116 = not found
    return data;
  }

  async getUserByKeycloakId(keycloakId: string) {
    const { data, error } = await this.supabase
      .from('users')
      .select('*')
      .eq('keycloak_id', keycloakId)
      .single();

    if (error && error.code !== 'PGRST116') throw error;
    return data;
  }

  // Sign-in attempts operations
  async createSignInAttempt(data: {
    user_id?: string;
    email: string;
    ip_address: string;
    country?: string;
    city?: string;
    region?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
    isp?: string;
    user_agent?: string;
    browser?: string;
    device?: string;
    os?: string;
    success: boolean;
    failure_reason?: string;
  }) {
    const { data: attempt, error } = await this.supabase
      .from('sign_in_attempts')
      .insert(data)
      .select()
      .single();

    if (error) throw error;
    return attempt;
  }

  async getSignInAttemptsByUserId(
    userId: string,
    limit: number = 50,
    offset: number = 0,
  ) {
    const { data, error } = await this.supabase
      .from('sign_in_attempts')
      .select('*')
      .eq('user_id', userId)
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;
    return data;
  }

  async getSignInAttemptsByEmail(
    email: string,
    limit: number = 50,
    offset: number = 0,
  ) {
    const { data, error } = await this.supabase
      .from('sign_in_attempts')
      .select('*')
      .eq('email', email)
      .order('timestamp', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;
    return data;
  }
}
