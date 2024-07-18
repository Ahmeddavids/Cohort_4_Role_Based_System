const express = require('express');
const { signUp, logIn, scoreStudent, makeAdmin, verifyEmail, resendVerificationEmail, forgotPassword, resetPassword, changePassword } = require('../controller/userController');
const { signUpValidator, logInValidator } = require('../middleware/validator');
const { authenticate } = require('../middleware/authentication');

const router = express.Router();

router.post('/sign-up', signUpValidator, signUp);

router.post('/sign-in', logInValidator, logIn);

router.put('/update-score/:id', authenticate, scoreStudent);

router.put('/make-admin/:id', makeAdmin);

router.get('/verify/:token', verifyEmail);

router.post('/resend-verification', resendVerificationEmail);
// Forgot password
router.post('/forgot-password', forgotPassword);
// Reset password
router.post('/reset-password/:token', resetPassword);
// Change password
router.post('/change-password/:token', changePassword);

module.exports = router