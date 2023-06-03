import { users } from '@/database/main';
import bcrypt from 'bcrypt';
import { Request, Response } from 'express';
import { validationResult } from 'express-validator';

class AuthController {
	static signUp = async (req: Request, res: Response) => {
		try {
			const { email, password } = req.body;
			const validation = validationResult(req);
			if (!validation.isEmpty()) {
				return res.status(400).json({
					message: 'Validation error',
					errors: validation.array(),
				});
			}
			const existingUser = await users.findOne({ email });
			if (existingUser) {
				return res.status(400).json({ message: 'User already exists' });
			}
			const hashPassword = await bcrypt.hash(password, 15);
			const user = {
				email: email,
				password: hashPassword,
			};
			await users.insertOne(user);
			return res.status(200).json({ message: 'User created' });
		} catch (e) {
			console.log(e);

			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
}

export default AuthController;
