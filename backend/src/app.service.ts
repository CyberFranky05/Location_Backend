import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Location Auth Backend API is running! Visit /api/v1/health for health check.';
  }
}
