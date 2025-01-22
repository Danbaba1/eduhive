export class SignupDto {
    email: string;
    password: string;
    name?: string;
    role?: 'ADMIN' | 'STUDENT';
  }
  
  export class LoginDto {
    email: string;
    password: string;
  }
