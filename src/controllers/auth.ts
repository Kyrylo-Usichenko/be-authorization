import { signUpCheck } from '@/middleware/auth';
import { Auth } from '@/services/auth';
import { Request, Response } from 'express';
import { validationResult } from 'express-validator';
import Controller from '.';

// class AuthController {
// 	static signUp = async (req: Request, res: Response) => {
// 		try {
// 			const { email, password } = req.body;
// 			const validation = validationResult(req);
// 			if (!validation.isEmpty()) {
// 				return res.status(400).json({
// 					message: 'Validation error',
// 					errors: validation.array(),
// 				});
// 			}
// 			const existingUser = await users.findOne({ email });
// 			if (existingUser) {
// 				return res.status(400).json({ message: 'User already exists' });
// 			}
// 			const hashPassword = await bcrypt.hash(password, 1);
// 			const user = {
// 				email: email,
// 				password: hashPassword,
// 			};
// 			await users.insertOne(user);
// 			const tokens = generateTokens(email);
// 			tokens && (await saveToken(email, tokens.refreshToken));
// 			return res.status(201).json({
// 				message: 'User created',
// 				accessToken: tokens?.accessToken,
// 				refreshToken: tokens?.refreshToken,
// 			});
// 		} catch (e) {
// 			console.log(e);
// 			res.status(500).json({ message: 'Something went wrong, try again' });
// 		}
// 	};
// 	static login = async (req: Request, res: Response) => {
// 		const { email, password } = req.body;
// 		const user = await users.findOne({ email });
// 		if (!user) return res.status(400).json({ message: 'User not found' });
// 		const isPasswordValid = await bcrypt.compare(password, user.password);
// 		if (!isPasswordValid)
// 			return res.status(400).json({ message: 'Invalid password' });
// 		const tokens = generateTokens(email);
// 		tokens && (await saveToken(email, tokens.refreshToken));
// 		return res.status(200).json({
// 			message: 'User logged in',
// 			accessToken: tokens?.accessToken,
// 			refreshToken: tokens?.refreshToken,
// 		});
// 	};
// 	static async refresh(req: Request, res: Response) {
// 		try {
// 			const { refreshToken } = req.body;
// 			if (!refreshToken)
// 				return res.status(400).json({ message: 'Token missed' });
// 			if (!process.env.REFRESH_TOKEN_SECRET)
// 				return res.status(500).json({ message: 'Something went wrong' });
// 			const isValid = validateToken(
// 				refreshToken,
// 				process.env.REFRESH_TOKEN_SECRET
// 			);
// 			const tokenFromDb = await tokens.findOne({ refreshToken });

// 			if (!isValid || !tokenFromDb) {
// 				return res.status(400).json({ message: 'User is unauthorized' });
// 			}
// 			const newTokens = generateTokens(tokenFromDb.email);
// 			if (!newTokens)
// 				return res.status(500).json({ message: 'Something went wrong' });
// 			await saveToken(tokenFromDb.email, newTokens.refreshToken);
// 			res.cookie('refreshToken', newTokens.refreshToken, {
// 				maxAge: 60 * 1000,
// 				httpOnly: true,
// 			});
// 			const data = {
// 				accessToken: newTokens.accessToken,
// 			};
// 			res.json(data);
// 		} catch (e) {
// 			console.log(e);
// 			res.status(500).json({ message: 'Something went wrong, try again' });
// 		}
// 	}
// 	static async me(req: Request, res: Response) {
// 		try {
// 			console.log(req.headers.authorization);

// 			const accessToken = req.headers.authorization?.split(' ')[1];

// 			if (!accessToken)
// 				return res.status(400).json({ message: 'Token missed' });
// 			if (!process.env.ACCESS_TOKEN_SECRET)
// 				return res.status(500).json({ message: 'Something went wrong' });
// 			const isValid = validateToken(
// 				accessToken,
// 				process.env.ACCESS_TOKEN_SECRET
// 			);
// 			if (!isValid) return res.status(400).json({ message: 'Invalid token' });
// 			return res.status(200).json({ message: 'User is authorized' });
// 		} catch (e) {
// 			console.log(e);
// 			res.status(500).json({ message: 'Something went wrong, try again' });
// 		}
// 	}
// }

class AuthController extends Controller {
	constructor(private auth: Auth) {
		super('/auth');
		this.router.post('/signup', signUpCheck, this.signUp);
		this.router.post('/login', signUpCheck, this.login);
		this.router.post('/refresh', this.refresh);
		this.router.get('/me', this.me);
	}
	private signUp = async (req: Request, res: Response) => {
		try {
			const { email, password } = req.body;
			const validation = validationResult(req);
			if (!validation.isEmpty()) {
				return res.status(400).json({
					message: 'Validation error',
					errors: validation.array(),
				});
			}
			await this.auth.signUp(email, password);
			return res.status(201).json({
				message: 'User created',
			});
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
	private login = async (req: Request, res: Response) => {
		const { email, password } = req.body;
		const tokens = await this.auth.login(email, password);
		return res.status(200).json({
			message: 'User logged in',
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken,
		});
	};
	private refresh = async (req: Request, res: Response) => {
		try {
			const { refreshToken } = req.body;
			if (!refreshToken)
				return res.status(400).json({ message: 'Token missed' });
			const accessToken = await this.auth.refresh(refreshToken);
			res.status(200).json({ accessToken });
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
	private me = (req: Request, res: Response) => {
		try {
			const accessToken = req.headers.authorization?.split(' ')[1];
			if (!accessToken)
				return res.status(400).json({ message: 'Token missed' });
			const email = this.auth.validate(accessToken);
			if (!email) return res.status(400).json({ message: 'Invalid token' });
			return res.status(200).json({ email });
		} catch (e) {
			console.log(e);
			res.status(500).json({ message: 'Something went wrong, try again' });
		}
	};
}
export default AuthController;
