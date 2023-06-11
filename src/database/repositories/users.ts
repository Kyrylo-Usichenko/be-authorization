export class Users {
	constructor(private collection: any) {}

	create = async (email: string, password: string) => {
		await this.collection.insertOne({
			email,
			password,
		});
	};

	get = async (email: string) => {
		return await this.collection.findOne({ email });
	};
}
