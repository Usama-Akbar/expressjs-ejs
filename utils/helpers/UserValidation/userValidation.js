const Joi = require('joi');

function userValidation(data){
    const schema = Joi.object({
        firstname: Joi.string().required(),
        lastname: Joi.string().required(),
        email: Joi.string().required(),
        password: Joi.string().required(),
    })
    return schema.validate(data);
}

module.exports = userValidation;