const express = require('express');

const router = express.Router();

router.get('/sign-in', (req, res) => {
  return res.json('Sign In');
})

router.get('/sign-up', (req, res) => {
  return res.json('Sign Up');
})

module.exports = router;