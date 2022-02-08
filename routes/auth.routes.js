const { Router } = require('express');
const router = new Router();

const bcryptjs = require('bcryptjs');
const saltRounds = 12;

const User = require('../models/User.model');
const mongoose = require('mongoose');

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');
 
// GET route to display the signup form to users
router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'));

// POST route to process form data
router.post('/signup', isLoggedOut, (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password){
        res.render('auth/signup', {errorMessage: 'All fields are mandatory. Please provide username and password.'});
        return;
    }

    // make sure passwords are strong:
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res
        .status(500)
        .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
        return;
    };
 
    bcryptjs
        .genSalt(saltRounds)
        .then(salt => bcryptjs.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                username,
                password: hashedPassword,
            });
        })
        .then(() => {
            res.redirect('/');
        })
        .catch(error => {
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            } else if (error.code === 11000){
                res.status(500).render('auth/signup', {
                    errorMessage: 'Username needs to be unique. Username is already used.'
                });
            } else {
                next(error);
            };
        });
});

// GET route for login
router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));

// POST route for login
router.post('/login', isLoggedOut, (req, res, next) => {
    const {username, password} = req.body;
    if (username === '' || password === ''){
        res.render('auth/login', {errorMessage: 'Please enter both, username and password to login.'});
        return;
    };
    User.findOne({username})
        .then(user => {
            if(!user){
                res.render('auth/login', { errorMessage: 'Username is not registered. Try with other username.' });
                return;
            } else if (bcryptjs.compareSync(password, user.password)){
                req.session.currentUser = user;
                res.redirect('/');
            } else {
                res.render('auth/login', { errorMessage: 'Incorrect password.' });
            };
        })
        .catch(error => next(error));
});

// POST route for logout
router.post('/logout', isLoggedIn, (req, res, next) => {
    req.session.destroy(err => {
        if (err) next(err);
        res.redirect('/');
    });
});
 
module.exports = router;