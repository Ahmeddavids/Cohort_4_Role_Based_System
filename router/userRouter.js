const express = require('express');
const { signUp, logIn, scoreStudent, makeAdmin, verifyEmail, resendVerificationEmail } = require('../controller/userController');
const { signUpValidator, logInValidator } = require('../middleware/validator');
const { authenticate } = require('../middleware/authentication');

const router = express.Router();

router.post('/sign-up', signUpValidator, signUp);

router.post('/sign-in', logInValidator, logIn);

router.put('/update-score/:id', authenticate, scoreStudent);

router.put('/make-admin/:id', makeAdmin);

router.get('/verify/:token', verifyEmail);

router.post('/resend-verification', resendVerificationEmail);

module.exports = router