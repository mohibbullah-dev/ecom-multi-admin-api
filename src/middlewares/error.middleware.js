import { ApiError } from "../utils/apiError.js";

export function notFound(req, res, next) {
  next(new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`));
}

export function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;

  // Zod errors come here via validate middleware
  const payload = {
    success: false,
    message: err.message || "Internal Server Error",
    errors: err.errors || null,
    stack: process.env.NODE_ENV === "production" ? undefined : err.stack,
  };

  res.status(statusCode).json(payload);
}
