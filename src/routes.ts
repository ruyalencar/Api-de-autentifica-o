import { Router } from 'express';

import authMiddleware from './app/middleware.ts/authMiddleware';

import UserController from './app/controllers/UserController';
import AuthController from './app/controllers/AuthController';


const router = Router();

router.get('/health', (req, res) => res.json({ message: 'OK' }))
router.post('/users', UserController.store);
router.post('/auth', AuthController.authenticate);
router.get('/users', authMiddleware, UserController.index);

export default router;
