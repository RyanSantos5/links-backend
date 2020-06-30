const express = require('express');
const bcrypt = require('bcrypt');
const  { Account} = require('../models');


const router = express.Router();

router.get('/sign-in', (req, res) => {
  return res.json('Sign In');
})

router.get('/sign-up', async(req, res) => {

  const email = 'emerson@SpeechGrammarList.com';
  const password = '123456'

  const saltRounds = 10;
  const hash = bcrypt.hashSync(password, saltRounds);
  console.log(hash);
  const result = await Account.create({email, password: hash})

  return res.json(result);
})

module.exports = router;