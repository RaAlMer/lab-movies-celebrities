const session = require('express-session');
const MongoStore = require('connect-mongo');
module.exports = app => {
    app.set('trust proxy', 1);
    app.use(
        session({
            secret: process.env.SESS_SECRET,
            resave: true,
            saveUninitialized: false,
            cookie: {
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                maxAge: 240000 // 60 * 1000 ms === 1 min
            },
            store: MongoStore.create({
                mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost/lab-express-basic-auth'
            })
        })
    );

    // Middle ware for making the user available to all templates
    app.use((req, res, next) => {
        res.locals.currentUser = req.session.currentUser;
        res.locals.messages = null;
        next();
    });
};