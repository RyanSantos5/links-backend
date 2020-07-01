const express = require('express');
const bcrypt = require('bcrypt');
const  { Account} = require('../models');
const  { accountSignUp , accountSignIn} = require('../validators/account');
const { getMessage } = require('../helpers/messages');
const {generateJwt, generateRefreshJwt , verifyJwt, verifyRefreshJwt} = require('../helpers/jwt');
const { version } = require('@hapi/joi');



const router = express.Router();
const saltRounds = 10;

router.post('/sign-in', accountSignIn, async (req, res) => {
  const {email, password} = req.body;
  const account = await Account.findOne({where: {email}});

  //Valida Senha
  const match = account ? bcrypt.compareSync(password, account.password) : null;
  if(!match) return res.jsonBadRequest(null, getMessage('account.signin.invalid'));

  const token = generateJwt({id: account.id});
  const refreshToken = generateRefreshJwt({id: account.id,  version: account.jwtVersion});

  return res.jsonOK(account, getMessage('account.signin.sucess'), {token, refreshToken});
});

router.post('/sign-up', accountSignUp, async(req, res) => {
  const {email, password} = req.body;
  
  const account = await Account.findOne({where: {email}});
  if(account) return res.jsonBadRequest(null, getMessage('account.signup.email_exists'));

  const hash = bcrypt.hashSync(password, saltRounds);
  const newAccount = await Account.create({email, password: hash});

  const token = generateJwt({id: newAccount.id});
  const refreshToken = generateRefreshJwt({id: newAccount.id, version: newAccount.jwtVersion});

  return res.jsonOK(newAccount , getMessage('account.signup.sucess'), {token, refreshToken});
});

module.exports = router;