const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local').Strategy;

if (!process.env.SECRET) {
  console.error('FATAL ERROR: SECRET is not defined.');
  process.exit(1);
}

function jsonExtractor(req) {
  let token = null;
  if (req && req.body) {
    token = req.body.token;
  }
  return token;
}

//from http://www.passportjs.org/packages/passport-jwt/
var JwtStrategy = require('passport-jwt').Strategy,
  ExtractJwt = require('passport-jwt').ExtractJwt;
var opts = {};
opts.jwtFromRequest = ExtractJwt.fromExtractors([jsonExtractor]);
opts.secretOrKey = process.env.SECRET;
passport.use(
  new JwtStrategy(opts, function(jwt_payload, done) {
    User.findOne({ email: jwt_payload.data }, function(err, user) {
      if (err) return done(err, false);
      if (user) return done(null, user);
      return done(null, false);
    });
  })
);

const Joi = require('@hapi/joi');
Joi.objectId = require('joi-objectid')(Joi);

const { User, validateUser } = require('./models/User');
const { Post } = require('./models/Post');

const app = express();

app.use(express.json());

mongoose.Promise = global.Promise;
mongoose
  .connect('mongodb://127.0.0.1', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Now connected to MongoDB!'))
  .catch(err => console.error('Something went wrong', err));

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      session: false,
    },
    async (email, password, done) => {
      const user = await User.findOne({ email });

      if (user) {
        const validPassword = await bcrypt.compare(password, user.password);
        if (email === user.email && validPassword) return done(null, user);
      }

      return done(null, false, { message: 'Invalid credentials.\n' });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

app.use(passport.initialize());

app.post('/api/login', passport.authenticate('local'), (req, res) => {
  let token = jwt.sign({ data: req.user.email }, process.env.SECRET, {
    expiresIn: 3600,
  });
  res.json({ token: token });
});

app.post('/api/signup', async (req, res) => {
  // First Validate The Request
  const { error } = validateUser(req.body);
  if (req.body === undefined) return res.status(400).json('Empty Request');
  if (error) return res.status(400).json(error.details[0].message);

  // Check if this user already exisits
  let user = await User.findOne({ email: req.body.email });
  if (user) return res.status(400).json('That user already exists!');

  const { name, email, password } = req.body;

  user = new User({ name, email, password });
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);

  await user.save();
  const token = jwt.sign({ data: req.body.email }, process.env.SECRET, {
    expiresIn: 3600,
  });

  res.json({ token });
});

app.get('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  let getPosts;

  if (req.body.own == true) {
    getPosts = await Post.find({ author: req.user._id });
  } else {
    getPosts = await Post.find({ author: { $in: req.user.friends } });
  }

  res.json(getPosts);
});

app.post('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  let newPost = new Post({
    author: req.user._id,
    slug: req.body.post,
    date: Date.now(),
  });

  newPost
    .save()
    .then(result => {
      return res.json(result);
    })
    .catch(err => {
      return res.status(400).json(err);
    });
});

app.post('/api/addFriend', passport.authenticate('jwt'), async (req, res) => {
  if (req.user.email == req.body.email)
    return res.status(400).json({
      msg: 'You can be your own friend but not on the platform, sorry',
    });

  let newFriend = await User.findOne({ email: req.body.email });

  if (!newFriend)
    return res.status(400).json({ msg: 'That user does not exist' });
  if (req.user.friends.includes(newFriend._id))
    return res.status(400).json({ msg: 'Already a friend' });

  req.user.friends.push(newFriend._id);
  req.user
    .save()
    .then(result => {
      return res.json(result);
    })
    .catch(err => {
      return res.status(400).json(err);
    });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
