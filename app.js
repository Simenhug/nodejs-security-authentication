require('dotenv').config();
const ejs = require("ejs");
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// level 2 security: encryption with a secret in .env file
const encrypt = require("mongoose-encryption");
// level 3 security: hashing
const md5 = require("md5");
// level 4 security: bcrypt hashing with salt rounds
const bcrypt = require("bcrypt");
const saltRounds = 10; // don't do too much 10 should be enough
// level 5 security: cookies and sessions
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
// session setting
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");
const Schema = mongoose.Schema;
const userSchema = new Schema({
    googleId: String,
    email: String,
    password: String, // level 1 security: passwords
    secret: String
});
// level 2 security: encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
// level 5
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model('user', userSchema);
passport.use(User.createStrategy());
// use static serialize and deserialize of model for passport session support
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //was an issue in 2019 but solved
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        // note: findOrCreate is not a function in passport module.
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            if (err) console.log(err);
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ secret: { $ne: null } }, function (err, users) {
        if (err) {
            console.log(err);
        } else {
            if (users) {
                res.render("secrets", { usersWithSecrets: users });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const secret = req.body.secret;
    User.findById(req.user.id, function (err, user) {
        if (err) {
            console.log(err);
        } else {
            if (user) {
                user.secret = secret;
                user.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate('local')(req, res, function () {
                // only enters here if authentication is successful
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (err) {
            res.send(err);
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) { res.send(err); }
        else {
            res.redirect("/");
        }
    });
});

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}
app.listen(port, function () {
    console.log("Server started on port " + port);
});