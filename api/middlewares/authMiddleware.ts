import jwt, { JwtPayload } from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import admin from "firebase-admin";

interface AuthRequest extends Request {
    userId?: string;
}

async function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    let token = req.cookies?.token;
    let userId: string | undefined;

    if (token) {
        try {
            const jwtSecret = process.env.JWT_SECRET;
            if (!jwtSecret) {
                throw new Error("JWT_SECRET no está definido en las variables de entorno");
            }
            const decodedToken = jwt.verify(token, jwtSecret) as JwtPayload & { userId: string };
            userId = decodedToken.userId;

        } catch (error: any) {
            res.status(401).json({ message: "Token inválido o expirado" });
            return;
        }
    } else {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ message: "No se proporcionó token de autenticación" });
            return;
        }
        const firebaseToken = authHeader.split('Bearer ')[1];
        try {
            // Verificar el Firebase ID token
            const decodedToken = await admin.auth().verifyIdToken(firebaseToken);
            userId = decodedToken.uid;
        } catch (error: any) {
            res.status(401).json({ message: "Token de Firebase inválido o expirado" });
            return;
        }
    }
    req.userId = userId;
    next();
}

export default authenticateToken;