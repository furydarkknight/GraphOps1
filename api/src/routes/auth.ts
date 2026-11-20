import { Router } from "express";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { validateBody } from "../middleware/validate.js";
import { authLimiter } from "../middleware/rate-limit.js";

export const authRouter = Router();

const RegisterSchema = z.object({
  name: z.string().min(2).max(100).trim(),
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(8).max(128),
  role: z.enum(["ANALYST", "RESPONDER", "SOC_MANAGER"]).optional().default("ANALYST"),
});

const LoginSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1),
});

function signToken(userId: string): string {
  const secret = process.env.JWT_SECRET!;
  return jwt.sign({}, secret, { subject: userId, expiresIn: "12h" });
}

// Register — only available when DEMO_MODE=true
authRouter.post(
  "/register",
  authLimiter,
  validateBody(RegisterSchema),
  async (req, res) => {
    if (process.env.DEMO_MODE !== "true") {
      return res
        .status(403)
        .json({ error: "Registration is disabled. Contact your SOC manager." });
    }

    const { name, email, password, role } = res.locals.body as z.infer<typeof RegisterSchema>;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await hash(password, 12);
    const user = await prisma.user.create({
      data: { name, email, passwordHash, role },
      select: { id: true, name: true, email: true, role: true, createdAt: true },
    });

    const token = signToken(user.id);
    return res.status(201).json({ token, user });
  },
);

// Login
authRouter.post(
  "/login",
  authLimiter,
  validateBody(LoginSchema),
  async (req, res) => {
    const { email, password } = res.locals.body as z.infer<typeof LoginSchema>;

    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, name: true, email: true, role: true, passwordHash: true },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const valid = await compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "LOGIN",
        actorId: user.id,
        payload: { email: user.email, role: user.role },
      },
    });

    const token = signToken(user.id);
    const { passwordHash: _, ...safeUser } = user;
    return res.json({ token, user: safeUser });
  },
);

// Whoami — returns current user from token
authRouter.get("/me", async (req, res) => {
  // requireAuth is applied at the app level for /api/auth/me separately
  if (!req.authUser) return res.status(401).json({ error: "Not authenticated." });
  const user = await prisma.user.findUnique({
    where: { id: req.authUser.id },
    select: { id: true, name: true, email: true, role: true, createdAt: true },
  });
  return res.json(user);
});
