const express = require('express');
const bcrypt = require('bcrypt');
const  { Account} = require('../models');
const account = require('../models/account');


const router = express.Router();
const saltRounds = 10;

router.get('/sign-in', (req, res) => {
  return res.json('Sign In');
});

router.get('/sign-up', async(req, res) => {
  const {email, password} = req.body;
  
  const account = await Account.findOne({where: {email}});
  if(account) return res.jsonBadRequest(null, 'Account already exist')

  const hash = bcrypt.hashSync(password, saltRounds);
  const newAccount = await Account.create({email, password: hash})
  return res.jsonOK(newAccount , 'Account created.');
});

module.exports = router;