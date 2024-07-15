const UserModel = require('../model/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendMail = require('../helpers/email');
const { signUpTemplate, verifyTemplate } = require('../helpers/emailTemplate');

exports.signUp = async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                message: 'User already exists'
            })
        }

        const saltedeRounds = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedeRounds);

        const user = new UserModel({
            fullName,
            email: email.toLowerCase(),
            password: hashedPassword
        })

        const userToken = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "20min" })
        const verifyLink = `${req.protocol}://${req.get("host")}/api/v1/user/verify/${userToken}`
        console.log(userToken);


        let mailOptions = {
            email: user.email,
            subject: 'Verification email',
            html: signUpTemplate(verifyLink, user.fullName),
        }

        await user.save();
        await sendMail(mailOptions);

        res.status(201).json({
            message: 'User created successfully',
            data: user
        })


    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}


exports.logIn = async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await UserModel.findOne({ email: email.toLowerCase() });
        if (!existingUser) {
            return res.status(404).json({
                message: 'User not found'
            })
        }

        const confirmPassword = await bcrypt.compare(password, existingUser.password);
        if (!confirmPassword) {
            return res.status(404).json({
                message: 'Incorrect Password'
            })
        }
        if (!existingUser.isVerified) {
            return res.status(400).json({
                message: 'User not verified, Please check you email to verify your account.'
            })
        }

        const token = await jwt.sign({
            userId: existingUser._id,
            email: existingUser.email
        }, process.env.JWT_SECRET, { expiresIn: '1h' })

        res.status(200).json({
            message: 'Login successfully',
            data: existingUser,
            token
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.scoreStudent = async (req, res) => {
    try {
        // Destructuring the required fields from the body
        const { html, CSS, javascript, remark } = req.body;
        // Get the student's ID from the params
        const studentId = req.params.id
        const student = await UserModel.findById(studentId);
        if (!student) {
            return res.status(404).json({
                message: 'Student not found'
            })
        }


        student.score.html = html || student.score.html
        student.score.CSS = CSS || student.score.CSS
        student.score.javascript = javascript || student.score.javascript
        student.score.remark = remark || student.score.remark

        await student.save()


        res.status(200).json({
            message: 'Student score updated successfully',
            data: student,
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.makeAdmin = async (req, res) => {
    try {
        const userId = req.params.id
        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        user.isAdmin = true
        await user.save()

        res.status(200).json({
            message: 'User now Admin',
            data: user,
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}


exports.verifyEmail = async (req, res) => {
    try {
        // Extract the token from the request params
        const { token } = req.params;
        // Extract the email from the verified token
        const { email } = jwt.verify(token, process.env.JWT_SECRET);
        // Find the user with the email
        const user = await UserModel.findOne({ email });
        // Check if the user is still in the database
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        // Check if the user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User already verified'
            })
        }
        // Verify the user
        user.isVerified = true;
        // Save the user data
        await user.save();
        // Send a success response
        res.status(200).json({
            message: 'User verified successfully'
        })

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.json({ message: 'Link expired.' })
        }
        res.status(500).json({
            message: error.message
        })
    }
}

exports.resendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;
        // Find the user with the email
        const user = await UserModel.findOne({ email });
        // Check if the user is still in the database
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }

        // Check if the user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User already verified'
            })
        }

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '20mins' });
        const verifyLink = `${req.protocol}://${req.get('host')}/api/v1/user/verify/${token}`
        let mailOptions = {
            email: user.email,
            subject: 'Verification email',
            html: verifyTemplate(verifyLink, user.fullName),
        }
        // Send the the email
        await sendMail(mailOptions);
        // Send a success message
        res.status(200).json({
            message: 'Verification email resent successfully'
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
