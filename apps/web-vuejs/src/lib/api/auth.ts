import type { User, LoginCredentials, RegisterData } from "@rbac/types";
import {
  login as clientLogin,
  register as clientRegister,
  logout as clientLogout,
  getCurrentUser as clientGetCurrentUser,
} from "./client";

export interface AuthResult {
  user: User;
}

export async function login(
  credentials: LoginCredentials,
): Promise<AuthResult> {
  const result = await clientLogin(credentials);
  return { user: result.user as User };
}

export async function register(data: RegisterData): Promise<AuthResult> {
  const result = await clientRegister(data);
  return { user: result.user as User };
}

export async function logout(): Promise<void> {
  await clientLogout();
}

export async function getCurrentUser(): Promise<User | null> {
  const user = await clientGetCurrentUser();
  return user as User | null;
}
