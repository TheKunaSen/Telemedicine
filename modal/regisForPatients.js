const mongoose = require("mongoose");
const UserSchema = new mongoose.Schema(
	{
		username: { type: "string", required: true, unique: true },
		password: { type: "string", required: true },
		firstname: { type: "string", required: true },
		lastname: { type: "string", required: true },
		number: { type: "string", required: true, unique: true},
		UserType: { type: "string", required: true},
		meet: { type: "string", required: true}
		
	},
	{ collection: "users" }
);

const model = mongoose.model("UserSchema", UserSchema);
module.exports = model;
