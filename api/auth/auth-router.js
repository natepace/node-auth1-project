// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const mw = require('./auth-middleware.js')
const User = require('../users/users-model.js')
const bcrypt = require('bcryptjs')


router.post('/register', mw.checkPasswordLength, mw.checkUsernameFree, (req, res, next) => {
  const { username, password } = req.body
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username: username, password: hash })
    .then(user => {
      res.status(200).json(user)
    })
    .catch(next)
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/login', mw.checkUsernameExists, mw.checkPasswordLength, async (req, res, next) => {
  const { username, password } = req.body
  const [user] = await User.findBy({ username })
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user
    res.status(200).json({ message: `welcome back ${username}` })
  }
  else { next({ status: 401, message: "invalid username or password" }) }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.get('/logout', (req, res) => {
  if (req.session && req.session.user) {
    req.session.destroy(() => {
      res.status(200).json({ message: "you have been logged out" })
    })
  }
  else {
    res.status(401).json({ message: 'no session found' })
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */


// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router