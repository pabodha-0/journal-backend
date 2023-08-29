import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  MinLength,
  IsOptional
} from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  @IsNotEmpty({ message: 'Please enter your email address' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Please enter an username' })
  @MinLength(4, { message: 'Username must be between 4-16 characters' })
  @MaxLength(16, { message: 'Username must be between 4-16 characters' })
  username: string;

  @IsString()
  @IsNotEmpty({ message: 'Please enter a password' })
  @MinLength(8, { message: 'Password must be between 8-32 characters' })
  @MaxLength(32, { message: 'Password must be between 8-32 characters' })
  password: string;

  @IsString()
  @IsNotEmpty({ message: 'Please enter your first name' })
  @MinLength(2, { message: 'Name must be between 2-32 characters' })
  @MaxLength(32, { message: 'Name must be between 2-32 characters' })
  firstName: string;

  @IsString()
  @IsNotEmpty({ message: 'Please enter your last name' })
  @MinLength(2, { message: 'Name must be between 2-32 characters' })
  @MaxLength(32, { message: 'Name must be between 2-32 characters' })
  lastName: string;

  @IsString()
  @IsOptional()
  imageURL: string;

  @IsString()
  @IsOptional()
  @Matches(
    /^(?:\+?\d{1,3}[\s-]?)?(?:\(\d{1,4}\)|\d{1,4})[\s-]?\d{1,4}[\s-]?\d{1,4}$/,
    { message: 'Please enter a valid phone number' }
  )
  mobileNum: string;
}

export class LoginUserDto {
  @IsEmail()
  @IsNotEmpty({ message: 'Please enter your email address' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Please enter a password' })
  password: string;
}
