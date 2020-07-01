const express = require('express');
const bcrypt = require('bcrypt');
const  { Account} = require('../models');
const  { accountSignUp , accountSignIn} = require('../validators/account');
const { getMessage } = require('../helpers/messages');
const {generateJwt, generateRefreshJwt , verifyJwt, verifyRefreshJwt, getTokenFromHeaders} = require('../helpers/jwt');
const { version } = require('@hapi/joi');



const router = express.Router();
const saltRounds = 10;

// LOGIN
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
// CADASTRO
router.post('/sign-up', accountSignUp, async(req, res) => {
  const {email, password} = req.body;
  
  // Verifica se ja existe
  const account = await Account.findOne({where: {email}});
  if(account) return res.jsonBadRequest(null, getMessage('account.signup.email_exists'));

  // Codifica a senha
  const hash = bcrypt.hashSync(password, saltRounds);
  const newAccount = await Account.create({email, password: hash});

  // Gera um token
  const token = generateJwt({id: newAccount.id});
  const refreshToken = generateRefreshJwt({id: newAccount.id, version: newAccount.jwtVersion});

  return res.jsonOK(newAccount , getMessage('account.signup.sucess'), {token, refreshToken});
});

router.post('/refresh', async (req, res) => {
  const token = getTokenFromHeaders(req.headers);
  if(!token) {
    return res.jsonUnathorized(null, 'Invalid token1');
  }

  try {
    const decoded = verifyRefreshJwt(token);
    const account = await Account.findByPk(decoded.id);
    if(!account) return res.jsonUnathorized(null, 'Invalid token2');

    if(decoded.version != account.jwtVersion){
      return res.jsonUnathorized(null, 'Invalid token3');
    }

    const meta = {
      token : generateJwt({id: account.id})
    };

    return res.jsonOK(null, null, meta);
  } catch (error) {
    return res.jsonUnathorized(null, 'Invalid token');
  }
  
});

module.exports = router;