import { Request, Response } from "express";
import { getRepository } from "typeorm";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from "../models/User";

class AuthController {
    async authenticate(req: Request, res: Response){
        const repository = getRepository(User);


        const user = await repository.findOne({ where: { email: req.body.email }});

        if (!user) {
            return res.sendStatus(401);
        }

        const isValidPassword = await bcrypt.compare(req.body.password, user.password); 

    
        if (!isValidPassword) {
            return res.sendStatus(401);
        }

        const token = jwt.sign({ id: user.id}, 'secret', { expiresIn: '1d' });

        const { id, email: userEmail } = user
      

        return res.json({
            user: { id, email: userEmail },
            token,
        });
    }

}

export default new AuthController();