import AuthController from '@/controllers/auth';
import { signUpCheck } from '@/middleware/auth';
import { Router } from 'express';

const router = Router();

router.post('/sign-up', signUpCheck, AuthController.signUp);

export default router;
