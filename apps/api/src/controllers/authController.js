import { registerSchema, loginSchema } from "../validators/auth.js";
import { loginUser, refreshToken, registerUser } from "../services/authService.js";
import { ok } from "../utils/response.js";

function setAuthCookie(res, token) {
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000 // 15 minutes
  });
}

export async function register(req, res) {
  const payload = registerSchema.parse(req.body);
  const result = await registerUser(payload);
  setAuthCookie(res, result.token);
  return ok(res, { id: result.id, email: result.email, role: result.role }, 201);
}

export async function login(req, res) {
  const payload = loginSchema.parse(req.body);
  const result = await loginUser(payload);
  setAuthCookie(res, result.token);
  return ok(res, { email: result.email });
}

export async function logout(req, res) {
  res.clearCookie("access_token");
  return ok(res, { message: "Logged out" });
}

export async function oauthCallback(req, res) {
  return ok(res, {
    provider: req.params.provider,
    status: "callback-received"
  });
}

export async function refresh(req, res) {
  const result = await refreshToken();
  setAuthCookie(res, result.token);
  return ok(res, { message: "Token refreshed" });
}
