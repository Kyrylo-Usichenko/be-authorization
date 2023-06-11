import { tokens } from '@/database';
import jwt from 'jsonwebtoken';

const generateTokens = (login: string) => {
	if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET)
		return;
	const accessSecret = process.env.ACCESS_TOKEN_SECRET;
	const refreshSecret = process.env.REFRESH_TOKEN_SECRET;
	const payload = {
		login,
	};
	const accessToken = jwt.sign(payload, accessSecret, {
		expiresIn: `${Math.floor(Math.random() * 31) + 30}s`,
	});
	const refreshToken = jwt.sign(payload, refreshSecret, { expiresIn: '1m' });
	return {
		accessToken,
		refreshToken,
	};
};

const saveToken = async (email: string, refreshToken: string) => {
	const tokenDate = await tokens.findOne({ email });
	if (tokenDate) {
		await tokens.updateOne(tokenDate, { $set: { refreshToken } });
	} else {
		await tokens.insertOne({
			email: email,
			refreshToken: refreshToken,
		});
	}
};

const validateToken = (token: string, secret: string) => {
	try {
		const decodeData = jwt.verify(token, secret);
		return decodeData;
	} catch (error) {
		return null;
	}
};
export { generateTokens, saveToken, validateToken };
