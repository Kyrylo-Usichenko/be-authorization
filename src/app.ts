import cors from 'cors';
import exress from 'express';
import router from './routers/auth';

const app = exress();
const port = 4321;
app.use(cors());
app.use(exress.json());

app.use('/', router);

app.listen(port, () => {
	console.log(`Server listening on port ${port}`);
});
