const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator');

const User = require('../models/user');

const transpoerter = nodemailer.createTransport(sendgridTransport({
    auth: {
        api_key: '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'
    }
}));

const errHandler = (err, next) => {
    const error = new Error(err);
    error.httpStatusCode = 500;
    return next(error);
}

const messageHandler = (req) => {
    let message = req.flash('error');
    return !!message.length ? message[0] : null;
}

exports.getLogin = (req, res, next) => {
    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: messageHandler(req),
        oldInput: {
            email: '',
            password: ''
        },
        validationErrors: []
    });
};

exports.getSignup = (req, res, next) => {
    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        errorMessage: messageHandler(req),
        oldInput: {
            email: '',
            password: '',
            confirmPassword: ''
        },
        validationErrors: []  
    });
};

exports.postLogin = (req, res, next) => {
    const { email, password } = req.body;
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: { email, password },
            validationErrors: errors.array()
        });
    }
    User.findOne({ email: email })
        .then(user => {
            if (!user) {
                return res.status(422).render('auth/login', {
                    path: '/login',
                    pageTitle: 'Login',
                    errorMessage: 'Email does not exist.',
                    oldInput: { email, password },
                    validationErrors: []
                });
            }
            bcrypt.compare(password, user.password)
                .then(doMatch => {
                    if (doMatch) {
                        req.session.isLoggedIn = true;
                        req.session.user = user;
                        return req.session.save(err => {
                            console.log(err);
                            return res.redirect('/');
                        });
                    }
                    return res.status(422).render('auth/login', {
                        path: '/login',
                        pageTitle: 'Login',
                        errorMessage: 'Invalid password.',
                        oldInput: { email, password },
                        validationErrors: []
                    });
                })
                .catch(err => {
                    res.redirect('/login');
                })
        })
        .catch(err => errHandler(err, next));
};

exports.postSignup = (req, res, next) => {
    const { email, password, confirmPassword } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/signup', {
            path: '/signup',
            pageTitle: 'Signup',
            errorMessage: errors.array()[0].msg,
            oldInput: { 
                email: email, 
                password: password, 
                confirmPassword: confirmPassword 
            },
            validationErrors: errors.array()
        });
    }
    bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
            const user = new User(
                {
                    email,
                    password: hashedPassword,
                    cart: { items: [] }
                }
            );
            return user.save();
        })
        .then(result => {
            res.redirect('/login');
            return transpoerter.sendMail({
                to: email,
                from: 'shop@node-complete.com',
                subject: 'Signup',
                html: '<h1>You successfully signed up!</h1>'
            });
        })
        .catch(err => errHandler(err, next));
};

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err);
        res.redirect('/');
    });
};

exports.getReset = (req, res, next) => {
    res.render('auth/reset', {
        path: '/reset',
        pageTitle: 'Reset Password',
        errorMessage: messageHandler(req)
    });
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            console.log(err);
            return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User.findOne({ email: req.body.email })
            .then(user => {
                if (!user) {
                    req.flash('error', 'No account with that email found.');
                    return res.redirect('/reset');
                }
                user.resetToken = token,
                user.resetTokenExpiration = Date.now() + 360000;
                return user.save();
            })
            .then(result => {
                transpoerter.sendMail({
                    to: req.body.email,
                    from: 'shop@node-complete.com',
                    subject: 'Signup',
                    html: `
            <p>You requested password reset</p>
            <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
          `
                });
                res.redirect('/');
            })
            .catch(err => errHandler(err, next));
    })
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;
    User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
        .then(user => {
            if (!!user) {
                return res.render('auth/new-password', {
                    path: '/new-password',
                    pageTitle: 'New Password',
                    errorMessage: messageHandler(req),
                    userId: user._id.toString(),
                    passwordToken: token
                })
            }
            req.flash('error', 'Not a valid token.');
            return res.redirect('/reset');
        })
        .catch(err => errHandler(err, next));
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password;
    const userId = req.body.userId;
    const passwordToken = req.body.passwordToken;
    let resetUser;

    User.findOne({
        resetToken: passwordToken,
        resetTokenExpiration: { $gt: Date.now() },
        _id: userId
    })
        .then(user => {
            resetUser = user;
            return bcrypt.hash(newPassword, 12);
        })
        .then(hashedPassword => {
            resetUser.password = hashedPassword;
            resetUser.resetToken = null;
            resetUser.resetTokenExpiration = undefined;
            return resetUser.save();
        })
        .then(result => {
            res.redirect('/login');
        })
        .catch(err => errHandler(err, next));
}
