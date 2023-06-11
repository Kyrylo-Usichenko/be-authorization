import { MongoClient } from 'mongodb';

const uri = process.env.DATABASE_URL;

if (!uri) {
	throw new Error('Database url not found');
}
const client = new MongoClient(uri);
const database = async () => {
	await client.connect();
};

database();

const db = client.db('be-authorization');
export const usersTable = db.collection('Users');
