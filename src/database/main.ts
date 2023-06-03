import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';

dotenv.config();

const uri = process.env.DATABASE_URL;
if (!uri) {
	throw new Error('Database url not found');
}
const client = new MongoClient(uri);
const database = async () => {
	await client.connect();
};
database();

export const db = client.db('be-authorization');
export const users = db.collection('Users');
