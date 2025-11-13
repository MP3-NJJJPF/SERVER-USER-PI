import jwt, { JwtPayload } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

interface AuthRequest extends Request {
    userId?: string; // añadimos el campo userId para usarlo luego
}

/**
 * Middleware to authenticate JWT tokens.
 * 
 * This middleware checks for the existence of a JWT token in cookies,
 * verifies it using the jwt_secret, and attaches the decoded
 * user ID to the request object for further usage in subsequent routes.
 * 
 * If the token is missing, invalid, or expired, it returns a 401 response.
 * 
 * @function authenticateToken
 * @param {import("express").Request} req - Express request object. Expects `req.cookies.token` to contain the JWT.
 * @param {import("express").Response} res - Express response object.
 * @param {import("express").NextFunction} next - Express next middleware function.
 * @returns {void} - Sends a 401 response if authentication fails, otherwise calls `next()`.
 */
function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
    // Get token from cookies
    const token = req.cookies?.token;

    //Verify if token exists
    if (!token) {
        res.status(401).json({ message: "No se proporcionó token de autenticación" });
        return;
    }

    try {
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            throw new Error("JWT_SECRET no está definido en las variables de entorno");
        }
        const decodedToken = jwt.verify(token, jwtSecret) as JwtPayload & { userId: string }; // decodedToken contains the payload (when the token was created)
        req.userId = decodedToken.userId; // Save userID in the request for further use (in other routes)
        next(); // Call the next middleware or route body
    } catch (error: any) {
        res.status(401).json({ message: "Token inválido o expirado" });
    }
}

export default authenticateToken;