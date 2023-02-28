import { Request, Response, NextFunction } from "express";
import Jwt from 'jsonwebtoken';

interface TokenPayload {
    id: string;
    iat: number;
    exp: number;
}

export default function authMiddleware(
    req: Request, res: Response, next: NextFunction,
) {
    const { authorization } = req.headers;

    if (!authorization) {
        return res.sendStatus(401);
    }

    const token = authorization.replace('Bearer', '').trim();

    try {
        const data = Jwt.verify (token, 'secret');
        
        const { id } = data as TokenPayload;

        req.userId = id;
        // Pegar token de autenticação da forma nativa do express
        // o split divide a string no valor que vc passar, eu coloquei um espaço vazio, ela retorna um array
        // no [1] eu peguei o segundo item do array que é o token, o primeiro vai ser a palavra Bearer
        //console.log('[Headers]', req.headers.authorization?.split(' ')[1])

        return next();
    } catch {
        return res.sendStatus(401);
    }
}