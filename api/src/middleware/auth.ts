import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.js";

// ─── Role hierarchy (order matters for requireMinRole) ────────────────────────
export type UserRole = "ANALYST" | "RESPONDER" | "SOC_MANAGER";
const ROLE_RANK: Record<UserRole, number> = {
  ANALYST: 0,
  RESPONDER: 1,
  SOC_MANAGER: 2,
};

export type AuthenticatedUser = {
  id: string;
  name: string;
  email: string;
  role: UserRole;
};

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthenticatedUser;
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  void authenticateRequest(req, res, next);
}

async function authenticateRequest(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "Authentication is not configured. Set a strong JWT_SECRET.",
    });
  }

  const authorization = req.headers.authorization;
  const token = authorization?.startsWith("Bearer ")
    ? authorization.slice(7).trim()
    : "";

  if (!token) {
    return res.status(401).json({ error: "A bearer token is required." });
  }

  let userId: string;
  try {
    const payload = jwt.verify(token, secret);
    if (typeof payload === "string" || !payload.sub) {
      return res.status(401).json({ error: "Invalid or expired token." });
    }
    userId = payload.sub;
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, name: true, email: true, role: true },
    });
    if (!user) {
      return res.status(401).json({ error: "User account no longer exists." });
    }
    req.authUser = { ...user, role: user.role as UserRole };
    return next();
  } catch {
    console.error("Authentication lookup failed.");
    return res.status(500).json({ error: "Unable to verify user account." });
  }
}

/** Require the user to have one of the listed roles exactly. */
export function requireRoles(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.authUser) {
      return res.status(401).json({ error: "Authentication is required." });
    }
    if (!roles.includes(req.authUser.role)) {
      return res.status(403).json({
        error: "Your role does not have permission to perform this action.",
      });
    }
    return next();
  };
}

/** Require at least the given role (ANALYST < RESPONDER < SOC_MANAGER). */
export function requireMinRole(minRole: UserRole) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.authUser) {
      return res.status(401).json({ error: "Authentication is required." });
    }
    if (ROLE_RANK[req.authUser.role] < ROLE_RANK[minRole]) {
      return res.status(403).json({
        error: "Your role does not have permission to perform this action.",
      });
    }
    return next();
  };
}
