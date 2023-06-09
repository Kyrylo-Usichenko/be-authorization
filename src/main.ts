import 'dotenv/config';
import App from './app';
import AuthController from './controllers/auth';
import { usersTable } from './database';
import { UsersRepository } from './database/repositories/users';
import { AuthService } from './services/auth';

const main = async () => {
	const users = new UsersRepository(usersTable);
	const authService = new AuthService(users);
	const authController = new AuthController(authService);

	const controllers = [authController];
	const app = new App(4321, controllers);

	app.start();
};
main();
