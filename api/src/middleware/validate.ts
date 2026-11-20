import type { NextFunction, Request, Response } from "express";
import { ZodSchema, ZodError } from "zod";

/**
 * Zod request-body validation middleware.
 * Returns 400 with structured errors on failure; calls next() on success
 * and attaches the parsed value to res.locals.body.
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: "Invalid request body.",
        issues: (result.error as ZodError).issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
      });
    }
    res.locals.body = result.data;
    return next();
  };
}

/** Zod query-param validation middleware. */
export function validateQuery<T>(schema: ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      return res.status(400).json({
        error: "Invalid query parameters.",
        issues: (result.error as ZodError).issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
      });
    }
    res.locals.query = result.data;
    return next();
  };
}
