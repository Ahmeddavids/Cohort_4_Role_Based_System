const Joi = require('@hapi/joi');

exports.signUpValidator = async (req, res, next) => {
    const schema = Joi.object({
        fullName: Joi.string().min(3).required().pattern(new RegExp( /^[A-Za-z]+(?: [A-Za-z]+)*$/)).messages({
            "any.required": "Fullname is required.",
            "string.empty": "Fullname cannot be an empty string.",
            "string.min": "Full name must be at least 3 characters long.",
            "string.pattern.base": "Full name cannot start or end with a whitespace.",
          }),
        email: Joi.string().trim().email().messages({
            "any.required": "Please provide your email address.",
            "string.empty": "Email address cannot be left empty.",
            "string.email": "Invalid email format. Please use a valid email address.",
        }),
        password: Joi.string().required().pattern(new RegExp("^(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$")).messages({
            "any.required": "Please provide a password.",
            "string.empty": "Password cannot be left empty.",
            "string.pattern.base":
            "Password must be at least 8 characters long and include at least one uppercase letter and one special character (!@#$%^&*).",
        }),
    })
    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            message: error.details[0].message
        })
    }

    next()
}

exports.logInValidator = async (req, res, next) => {
    const schema = Joi.object({
        email: Joi.string().trim().email().required().messages({
            "any.required": "Please provide your email address.",
            "string.empty": "Email address cannot be left empty.",
            "string.email": "Invalid email format. Please use a valid email address.",
        }),
        password: Joi.string().required().pattern(new RegExp("^(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$")).messages({
            "any.required": "Please provide a password.",
            "string.empty": "Password cannot be left empty.",
            "string.pattern.base":
            "Password must be at least 8 characters long and include at least one uppercase letter and one special character (!@#$%^&*).",
        }),
    })
    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            message: error.details[0].message
        })
    }

    next()
}
