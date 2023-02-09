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
const e = require('express');


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
    email: String,
    password: String // level 1 security: passwords
});
// level 2 security: encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

// level 5
userSchema.plugin(passportLocalMongoose);
const User = mongoose.model('user', userSchema);
passport.use(User.createStrategy());
// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
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