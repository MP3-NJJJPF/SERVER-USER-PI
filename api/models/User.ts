/**
 * Represents a user document stored in Firestore.
 * 
 * Firebase Authentication manages credentials (email, password),
 * while Firestore holds user profile and application-specific data.
 */

import { Timestamp } from "firebase-admin/firestore";

/**
 * Interface that defines the shape of a user stored in Firestore.
 */
export interface IUser {
  /** Firebase Auth unique ID */
  uid?: string;

  /** User's first name */
  firstName: string;

  /** User's last name */
  lastName: string;

  /** User's age (must be >= 13) */
  age: number;

  /** Email (must match the Firebase Auth user) */
  email: string;

  /** Hashed password */
  password?: string;

  /** token used for password reset flows */
  resetPasswordToken?: string | null;

  /** Expiration date for password reset token */
  resetPasswordExpires?: Date | null;

  /** Role of the user in the application */
  role?: "admin" | "user" | "staff";

  /** Whether the user account is active */
  isActive?: boolean;

  /** Date when the user was created */
  createdAt?: Timestamp;

  /** Date when the user was last updated */
  updatedAt?: Timestamp;
}

/**
 * Type used for creating a user (input validation in services/DAO).
 */
export type IUserCreate = Omit<
  IUser,
  "uid" | "createdAt" | "updatedAt" | "resetPasswordToken" | "resetPasswordExpires"
>;

/**
 * Type used when updating user data.
 */
export type IUserUpdate = Partial<Omit<IUser, "uid" | "createdAt">>;