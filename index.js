/* eslint-disable no-console */
/* eslint-disable consistent-return */
/* eslint-disable no-param-reassign */
/* eslint-disable no-underscore-dangle */
const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');

if (!process.env.SECRET) {
  console.error('FATAL ERROR: SECRET is not defined.');
  process.exit(1);
}
if (!process.env.MONGO) {
  console.error('FATAL ERROR: MONGO is not defined.');
  process.exit(1);
}

// function jsonExtractor(req) {
//   let token = null;
//   if (req && req.body) {
//     token = req.body.token;
//   }
//   return token;
// }

const Joi = require('@hapi/joi');
Joi.objectId = require('joi-objectid')(Joi);

const { User, validateUser } = require('./models/User');
const { Post } = require('./models/Post');

const app = express();

app.use(cors());

app.use(express.json());

mongoose.Promise = global.Promise;
mongoose
  .connect(process.env.MONGO, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Now connected to MongoDB!'))
  .catch((err) => console.error('Something went wrong', err));

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
    },
  ),
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// from http://www.passportjs.org/packages/passport-jwt/
const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.SECRET;
passport.use(
  new JwtStrategy(opts, (jwtPayload, done) => {
    User.findOne({ email: jwtPayload.data }, (err, user) => {
      if (err) return done(err, false);
      if (user) return done(null, user);
      return done(null, false);
    });
  }),
);

app.use(passport.initialize());

app.post('/api/login', passport.authenticate('local'), (req, res) => {
  const token = jwt.sign({ data: req.user.email }, process.env.SECRET, {
    expiresIn: 3600,
  });
  res.json({ token, user: req.user.name, id: req.user._id });
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

  return res.json({ token, user: user.name, id: user._id });
});

app.get('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  let getPosts;

  if (req.query.own === '0') {
    // Only own posts
    // eslint-disable-next-line no-underscore-dangle
    getPosts = await Post.find({ creator: req.user._id }).sort({
      date: -1,
    });
  } else if (req.query.own === '1') {
    // Only Public Friends posts
    getPosts = await Post.find({
      creator: { $in: req.user.friends },
      public: true,
    }).sort({
      date: -1,
    });
  } else if (req.query.own === '2') {
    getPosts = await Post.find({
      // Own posts + Public Friends
      $or: [
        { creator: req.user._id },
        { creator: { $in: req.user.friends }, public: true },
      ],
    }).sort({
      date: -1,
    });
  } else if (req.query.own === '3') {
    const getUsers = await User.find({ friends: req.user._id });
    const test = getUsers.map((el) => el._id.toString());
    const filteredFriends = req.user.friends.filter((el) => test.includes(el.toString()));

    getPosts = await Post.find({
      // Own posts + Public Friends + Private from mutuals
      $or: [
        { creator: req.user._id },
        { creator: { $in: req.user.friends }, public: true },
        { creator: { $in: filteredFriends }, public: false },
      ],
    }).sort({
      date: -1,
    });
  }

  res.json(getPosts);
});

app.post('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  const newPost = new Post({
    author: req.user.name,
    creator: req.user._id,
    slug: req.body.post,
    date: Date.now(),
    public: req.body.public,
  });

  newPost
    .save()
    .then((result) => res.json(result))
    .catch((err) => res.status(400).json(err));
});

app.delete('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  const checkPost = await Post.findOne({ _id: req.query.id });

  if (!checkPost) {
    return res.status(400).json({ msg: 'Post does not exist' });
  }

  if (checkPost.creator.toString() !== req.user._id.toString()) {
    return res.status(400).json({ msg: 'Not your post' });
  }
  // eslint-disable-next-line no-underscore-dangle
  Post.deleteOne({ creator: req.user._id, _id: req.query.id })
    .then((result) => res.json(result))
    .catch((err) => res.status(400).json(err));
});

app.patch('/api/posts', passport.authenticate('jwt'), async (req, res) => {
  const checkPost = await Post.findOne({ _id: req.body.id });

  if (!checkPost) {
    return res.status(400).json({ msg: 'Post does not exist' });
  }

  if (checkPost.creator.toString() !== req.user._id.toString()) {
    return res.status(400).json({ msg: 'Not your post' });
  }
  // eslint-disable-next-line no-underscore-dangle
  Post.findOne({ creator: req.user._id, _id: req.body.id })
    .then(async (result) => {
      result.slug = req.body.slug;
      result.date = Date.now();
      await result.save();
      return res.json(result);
    })
    .catch((err) => res.status(400).json(err));
});

app.post('/api/addFriend', passport.authenticate('jwt'), async (req, res) => {
  if (req.user.email === req.body.email) {
    return res.status(400).json({
      msg: 'You can be your own friend but not on the platform, sorry',
    });
  }

  const newFriend = await User.findOne({ email: req.body.email });

  if (!newFriend) {
    return res.status(400).json({ msg: 'That user does not exist' });
  }
  if (req.user.friends.includes(newFriend._id)) {
    return res.status(400).json({ msg: 'Already a friend' });
  }

  req.user.friends.push(newFriend._id);
  req.user
    .save()
    .then((result) => res.json(result))
    .catch((err) => res.status(400).json(err));
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
