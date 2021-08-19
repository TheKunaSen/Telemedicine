/* CONFIGURATION */

var OpenVidu = require('openvidu-node-client').OpenVidu;
var OpenViduRole = require('openvidu-node-client').OpenViduRole;

// Check launch arguments: must receive openvidu-server URL and the secret
if (process.argv.length != 4) {
    console.log("Usage: node " + __filename + " OPENVIDU_URL OPENVIDU_SECRET");
    process.exit(-1);
}
// For demo purposes we ignore self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

// Node imports
var fast2sms = require("fast-two-sms");
require("dotenv").config();
var mongoose = require("mongoose");



const Patients = require("./modal/regisForPatients.js");
const Doctors = require("./modal/regisForDoctors.js");
const Staff = require("./modal/regisForStaff.js");
const bcrypt = require("bcryptjs");
var express = require('express');
var fs = require('fs');
var session = require('express-session');
var http = require('http');
var bodyParser = require('body-parser'); // Pull information from HTML POST (express4)
var app = express(); // Create our app with express

// Server configuration
app.use(session({
    saveUninitialized: true,
    resave: false,
    secret: 'MY_SECRET'
}));
app.use(express.static(__dirname + '/public')); // Set the static files location
app.use(bodyParser.urlencoded({
    'extended': 'true'
})); // Parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // Parse application/json
app.use(bodyParser.json({
    type: 'application/vnd.api+json'
})); // Parse application/vnd.api+json as json
app.set('view engine', 'ejs'); // Embedded JavaScript as template engine

// Listen (start app with node server.js)
var options = {
    key: fs.readFileSync('openvidukey.pem'),
    cert: fs.readFileSync('openviducert.pem')
};
http.createServer(options, app).listen(8080);

// Mock database
var users = [{
    user: "publisher1",
    pass: "pass",
    role: OpenViduRole.PUBLISHER
},  {
    user: "publisher2",
    pass: "pass",
    role: OpenViduRole.PUBLISHER
}];

// Environment variable: URL where our OpenVidu server is listening
var OPENVIDU_URL = process.argv[2];
// Environment variable: secret shared with our OpenVidu server
var OPENVIDU_SECRET = process.argv[3];

// Entrypoint to OpenVidu Node Client SDK
var OV = new OpenVidu(OPENVIDU_URL, OPENVIDU_SECRET);

// Collection to pair session names with OpenVidu Session objects
var mapSessions = {};
// Collection to pair session names with tokens
var mapSessionNamesTokens = {};

console.log("App listening on port 8080");

/* CONFIGURATION */



/* REST API */
mongoose.connect("mongodb://Localhost:27017/testx2", {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
});
var db = mongoose.connection;
db.on("error", () => console.log("Error in connecting to Mongo"));
db.once("open", () => console.log("Connected to database"));








app.post('/',(req, res)=>{
	res.render('login.ejs');
});
app.get('/',(req, res)=>{
	res.render('login.ejs');
});


















app.post("/signup", async (req, res, cb) => {
	
	console.log(req.body.number);
	usernumberreg = await Patients.findOne({ number: req.body.number }).lean();
	usernumberreg2 = await Staff.findOne({ number: req.body.number }).lean();
	usernumberreg3 = await Doctors.findOne({ number: req.body.number }).lean();
	if (
		usernumberreg == null &&
		usernumberreg2 == null &&
		usernumberreg3 == null
	) {
		var firstName = req.body.first;
		var lastName = req.body.last;
		var username = req.body.username;
		 chcekname = req.body.username;
		var password = req.body.password;
		var number = req.body.number;
		var userType = req.body.type;
		var password = await bcrypt.hash(password, 10);
var meet = "nonep";
		data = {
			firstname: firstName,
			lastname: lastName,
			username: username,
			password: password,
			number: number,
			meet: meet,
			UserType: userType,
			
			
		};
		otp = Math.floor(1000 + Math.random() * 9000);
		console.log(otp);
		const response = await fast2sms.sendMessage({
			authorization: process.env.API_KEY,
			message: otp,
			numbers: [req.body.number]
		});
		console.log(response);
		console.log(Object.values(data)[Object.values(data).length - 1]);
		// console.log(req.body.type);
		return res.render("otp.ejs");
	} else {
		res.render("noreg.ejs", {
			name: "dear user",
			message: "this number is already registered",
			bod: "login",
			linkm: "go to login",
			title: "Already registered"
		});
	}
});
app.post("/otpind", async (req, res) => {
	var otpen = req.body.otpin;

	// console.log(otpen, otp);
	if (otpen == otp) {
		console.log(chcekname);
		if(( await Doctors.findOne({ username: chcekname }).lean()==null)&&( await Staff.findOne({ username: chcekname }).lean()==null)&& (await Patients.findOne({ username: chcekname }).lean()==null)) {
			try {
				if (Object.values(data)[Object.values(data).length - 1] == "Patient") {
					const respon = await Patients.create(data);
					console.log(`successfully registered ${respon}`);
				} 
				else if (
					Object.values(data)[Object.values(data).length - 1] == "Doctor"
				) {
					const respon = await Doctors.create(data);
					console.log(`successfully registered ${respon}`);
				} else if (
					Object.values(data)[Object.values(data).length - 1] == "staff"
				) {
					const respon = await Staff.create(data);
					console.log(`successfully registered ${respon}`);
				}
			} catch (e) {
				//   console.log(e);
				if (e.code === 11000) {
					console.log("username taken");
					 res.render("noreg.ejs", {
						name: "dear user",
						message: "the username is already taken",
						bod: "regis",
						linkm: "try again",
						title: "taken"
					});
				}
				throw e;
			}
			console.log(Object.values(data)[Object.values(data).length - 1]);
			return res.render("finish.ejs");
	}
	else {
		console.log("username taken");
		res.render("noreg.ejs", {
		   name: "dear user",
		   message: "the username is already taken",
		   bod: "regis",
		   linkm: "try again",
		   title: "taken"
	   });
	
	}
		
	
	} else {
		otp = Math.floor(1000 + Math.random() * 9000);
		console.log("try again");
		res.render("regis.ejs");
	}
});




app.post("/logind", async (req, res) => {
	console.log("Going to logind page");
	const loginuser = req.body.loginname;
	const loginpow = req.body.loginpow;
	const patientlogin = await Patients.findOne({ username: loginuser }).lean();
	const doctorlogin = await Doctors.findOne({ username: loginuser }).lean();
	const stafflogin = await Staff.findOne({ username: loginuser }).lean();
	// console.log(userlogin);
	if (patientlogin != null) {
		utype="patient";
		ViewName=patientlogin.firstname + " " + patientlogin.lastname;
		if (await bcrypt.compare(loginpow, patientlogin.password)) {
			console.log("logged in");
			dctrlist=await Doctors.find().lean();
			arr1=[];
			
			dctrlist.forEach((dctr) => {
				
// console.log(dctr.firstname);
mainname=dctr.firstname+" "+dctr.lastname;
// console.log(mainname);

arr1.push(mainname);
			});
			
			// console.log(arr1);
			res.render("logged.ejs", {
				dct:arr1,
				name: "",
				message:
					"Hi! " +
					patientlogin.UserType +
					" " +
					loginuser +
					" You are logged in",
				bod: "login",
				linkm: "exit",
				title: "Welcome"
			});
		} else {
			console.log("wrong password");
			res.render("noreg.ejs", {
				name: loginuser,
				message: "your password is incorrect",
				bod: "login",
				linkm: "Try again",
				title: "Wrong password"
			});
		}
	} else if (doctorlogin != null) {
		utype="doctor";
		ViewName=doctorlogin.firstname + " " + doctorlogin.lastname;
		if (await bcrypt.compare(loginpow, doctorlogin.password)) {
			console.log("logged in");
			
		
			res.render("noreg.ejs", {
				name: "",
				message:
					"Hi! " +
					doctorlogin.UserType +
					" " +
					loginuser +
					" You are logged in",
				bod: "login",
				linkm: "exit",
				title: "Welcome"
			});
			
		}
		else {
			console.log("wrong password");
			res.render("noreg.ejs", {
				name: loginuser,
				message: "your password is incorrect",
				bod: "login",
				linkm: "Try again",
				title: "Wrong password"
			});
		}
	} 
	else if (stafflogin != null) {
		utype="staff";
		ViewName=stafflogin.firstname + " " + stafflogin.lastname;
		if (await bcrypt.compare(loginpow, stafflogin.password)) {
			console.log("logged in");
			
			
			res.render("noreg.ejs", {
				name: "",
				message:
					"Hi! " +
					stafflogin.UserType +
					" " +
					loginuser +
					" You are logged in",
				bod: "login",
				linkm: "exit",
				title: "Welcome"
			});
			
		}
		else {
			console.log("wrong password");
			res.render("noreg.ejs", {
				name: loginuser,
				message: "your password is incorrect",
				bod: "login",
				linkm: "Try again",
				title: "Wrong password"
			});
		}
	}
	else {
		console.log("not registered");
		res.render("noreg.ejs", {
			name: loginuser,
			message: "you are not registered",
			bod: "regis",
			linkm: "Go register yourself",
			title: "Not registered"
		});
	}
});
app.get("/forget", async (req, res) => {
	res.render("forget.ejs");
});
app.post("/forgetotp", async (req, res) => {
	forgetnum=req.body.forgetnumber;
	patientnumber = await Patients.findOne({ number: forgetnum }).lean();
	doctornumber = await Doctors.findOne({ number: forgetnum }).lean();
	staffnumber = await Staff.findOne({ number: forgetnum }).lean();
	if (patientnumber != null) {
		otp = Math.floor(1000 + Math.random() * 9000);
		console.log(otp);
		const response = await fast2sms.sendMessage({
			authorization: process.env.API_KEY,
			message: otp,
			numbers: [req.body.forgetnumber]
		});
		console.log(response);
		usernumber=patientnumber;
		updatedb=Patients;
		res.render("otpforget.ejs");
	}
	else if (doctornumber != null) {
		otp = Math.floor(1000 + Math.random() * 9000);
		console.log(otp);
		const response = await fast2sms.sendMessage({
			authorization: process.env.API_KEY,
			message: otp,
			numbers: [req.body.forgetnumber]
		});
		updatedb=Doctors;
		usernumber=doctornumber;
		console.log(response);
		res.render("otpforget.ejs");
	}
	else if (staffnumber != null) {
		otp = Math.floor(1000 + Math.random() * 9000);
		console.log(otp);
		const response = await fast2sms.sendMessage({
			authorization: process.env.API_KEY,
			message: otp,
			numbers: [req.body.forgetnumber]
		});
		updatedb=Staff;
		usernumber=staffnumber;
		console.log(response);
		res.redirect("otpforget.ejs");
	}
	else {
		res.render("noreg.ejs", {
			name: "dear user",
			message: "you are not registered",
			bod: "regis",
			linkm: "Go register yourself",
			title: "Not registered"
		});
	}
});

app.post("/otpforget", async (req, res) => {
	if (otp == req.body.otpinforget) {
		res.render("newpass.ejs");
	} else {
		res.render("noreg.ejs", {
			name: " ",
			message: "wrong otp",
			bod: "forget",
			linkm: "try again",
			title: "invalid otp"
		});
	}
});
app.post("/newpass", async (req, res) => {
	console.log(usernumber._id);
	// console.log(req.body.newpass);
	var newpassword = await bcrypt.hash(req.body.newpass, 10);
	console.log(newpassword);
	// const updatelog = await updatedb.findOne({ mumber: forgetnum }).lean();
	const updatepass = async _id => {
		const result = await updatedb.updateOne(
			{ _id },
			{
				$set: {
					password: newpassword
				}
			}
		);
		console.log("updated successfully");
	};
	updatepass(usernumber._id);
	res.render("noreg.ejs", {
		name: "dear "+ usernumber.username,
		message: " your password is updated successfully",
		bod: "login",
		linkm: "Go to login",
		title: "password updated"
	});
});

app.post("/selected", (req, res) => {


});





app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/login', (req, res) => {
	console.log("Going to login page");
	res.render('login.ejs',);
	
});
app.get("/regis", (req, res) => {
	console.log("Going to regis page");
	res.render('regis.ejs');
});
// app.post("/regis", (req, res) => {
// 	console.log("Going to regis page");
// 	res.redirect('regis.ejs');
// });

app.post('/logind/meet', loginController);
app.get('/logind/meet', loginController);

async function loginController(req, res) {
	console.log(req.body.opts);
	dcit=req.body.opts;
	doctorfind = await Doctors.findOne({ firstname: dcit }).lean();
	console.log(utype);
	if (utype == "patient"){
	const updatepasst = async _id => {
		const result = await Doctors.updateOne(
			{ _id },
			{
				$set: {
					meet: ViewName
				}
			}
		);
		console.log("updated successfully");
	};
	updatepasst(doctorfind._id);
}
else if (utype == "doctor") {
	console.log(utype);
}
	res.redirect('/dashboard');
}

app.post('/dashboard', dashboardController);
app.get('/dashboard', dashboardController);

function dashboardController(req, res) {

    // // Check if the user is already logged in
    // if (isLogged(req.session)) {
    //     // User is already logged. Immediately return dashboard
    //     user = req.session.loggedUser;
    //     res.render('dashboard.ejs', {
    //         user: user
    //     });
    // } else {
        // User wasn't logged and wants to

        // Retrieve params from POST body
        // var user = req.body.user;
        // var pass = req.body.pass;
        // console.log("Logging in | {user, pass}={" + user + ", " + pass + "}");

        // if (login(user, pass)) { // Correct user-pass
        //     // Validate session and return OK
        //     // Value stored in req.session allows us to identify the user in future requests
        //     console.log("'" + user + "' has logged in");
	
		user='publisher1';
            req.session.loggedUser = user;
            res.render('dashboard.ejs', {
				user: ViewName
			});
        // } else { // Wrong user-pass
        //     // Invalidate session and return index template
        //     console.log("'" + user + "' invalid credentials");
        //     req.session.destroy();
        //     res.redirect('/');
        // }
    // }
}

app.post('/session', (req, res) => {
 
        // The nickname sent by the client
		console.log(ViewName);
        var clientData = ViewName;
        // The video-call to connect

        var sessionName = req.body.sessionname;

        // Role associated to this user
        // var role = users.find(u => (u.user === req.session.loggedUser)).role;
console.log(req.session.loggedUser);
        // Optional data to be passed to other users when this user connects to the video-call
        // In this case, a JSON with the value we stored in the req.session object on login
        var serverData = JSON.stringify({ serverData: req.session.loggedUser });

        console.log("Getting a token | {sessionName}={" + sessionName + "}");

        // Build connectionProperties object with the serverData and the role
        var connectionProperties = {
            data: serverData,
            role: OpenViduRole.PUBLISHER
        };

        if (mapSessions[sessionName]) {
            // Session already exists
            console.log('Existing session ' + sessionName);

            // Get the existing Session from the collection
            var mySession = mapSessions[sessionName];

            // Generate a new token asynchronously with the recently created connectionProperties
            mySession.createConnection(connectionProperties)
                .then(connection => {

                    // Store the new token in the collection of tokens
                    mapSessionNamesTokens[sessionName].push(connection.token);

                    // Return session template with all the needed attributes
                    res.render('session.ejs', {
                        sessionId: mySession.getSessionId(),
                        token: connection.token,
                        nickName: clientData,
                        userName: req.session.loggedUser,
                        sessionName: sessionName
                    });
                })
                .catch(error => {
                    console.error(error);
                });
        } else {
            // New session
            console.log('New session ' + sessionName);

            // Create a new OpenVidu Session asynchronously
            OV.createSession()
                .then(session => {
                    // Store the new Session in the collection of Sessions
                    mapSessions[sessionName] = session;
                    // Store a new empty array in the collection of tokens
                    mapSessionNamesTokens[sessionName] = [];

                    // Generate a new token asynchronously with the recently created connectionProperties
                    session.createConnection(connectionProperties)
                        .then(connection => {

                            // Store the new token in the collection of tokens
                            mapSessionNamesTokens[sessionName].push(connection.token);

                            // Return session template with all the needed attributes
                            res.render('session.ejs', {
                                sessionName: sessionName,
                                token: connection.token,
                                nickName: clientData,
                                userName: req.session.loggedUser,
                            });
                        })
                        .catch(error => {
                            console.error(error);
                        });
                })
                .catch(error => {
                    console.error(error);
                });
        }
    
});

app.post('/leave-session', (req, res) => {
    // if (!isLogged(req.session)) {
    //     req.session.destroy();
    //     res.render('index.ejs');
    // } else {
        // Retrieve params from POST body
        var sessionName = req.body.sessionname;
        var token = req.body.token;
        console.log('Removing user | {sessionName, token}={' + sessionName + ', ' + token + '}');

        // If the session exists
        if (mapSessions[sessionName] && mapSessionNamesTokens[sessionName]) {
            var tokens = mapSessionNamesTokens[sessionName];
            var index = tokens.indexOf(token);

            // If the token exists
            if (index !== -1) {
                // Token removed
                tokens.splice(index, 1);
                console.log(sessionName + ': ' + tokens.toString());
            } else {
                var msg = 'Problems in the app server: the TOKEN wasn\'t valid';
                console.log(msg);
                res.redirect('/dashboard');
            }
            if (tokens.length == 0) {
                // Last user left: session must be removed
                console.log(sessionName + ' empty!');
                delete mapSessions[sessionName];
            }
            res.redirect('/dashboard');
        } else {
            var msg = 'Problems in the app server: the SESSION does not exist';
            console.log(msg);
            res.status(500).send(msg);
        }
    // }
});

/* REST API */



/* AUXILIARY METHODS */

// function login(user, pass) {
//     return (user != null &&
//         pass != null &&
//         users.find(u => (u.user === user) && (u.pass === pass)));
// }

// function isLogged(session) {
//     return (session.loggedUser != null);
// }

function getBasicAuth() {
    return 'Basic ' + (new Buffer('OPENVIDUAPP:' + OPENVIDU_SECRET).toString('base64'));
}

/* AUXILIARY METHODS */
