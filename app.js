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

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


mongoose.connect("mongodb://127.0.0.1:27017/userDB");
const Schema = mongoose.Schema;
const userSchema = new Schema({
    email: String,
    password: String // level 1 security: passwords
});
// level 2 security: encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
const User = mongoose.model('user', userSchema);

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.post("/register", function (req, res) {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.username,
            // password: md5(req.body.password) // hashing
            password: hash
        });
        newUser.save(function (err) {
            if (err) {
                res.status(500).send(err);
            } else {
                res.render("secrets");
            }
        });
    });
});

app.post("/login", function (req, res) {
    const username = req.body.username;
    const plainTextPwd = req.body.password;

    User.findOne({ email: username }, function (err, user) {
        if (err) {
            res.status(500).send(err);
        } else {
            if (user) {
                bcrypt.compare(plainTextPwd, user.password, function(err, result) {
                    if (result) {
                        res.render("secrets");
                    } else {
                        res.status(401).send("incorrect credential");
                    }
                });
            } else {
                res.status(401).send("username not found");
            }
        }
    });
});

app.get("/logout", function (req, res) {
    res.render("home");
});


let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}
app.listen(port, function () {
    console.log("Server started on port " + port);
});