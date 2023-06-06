import AuthController from '@/controllers/auth';
import { signUpCheck } from '@/middleware/auth';
import { Router } from 'express';

const router = Router();

router.post('/sign-up', signUpCheck, AuthController.signUp);
router.post('/login', AuthController.login);
router.post('/refresh', AuthController.refresh);
router.post('/me', AuthController.me);

export default router;
