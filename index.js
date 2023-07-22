const express = require('express');
const app = express();
const cors = require('cors');
const pool = require('./db');
const nodemailer = require('nodemailer');
var bcrypt = require('bcrypt');
const fs = require('fs');
const moment = require('moment-timezone');
const generateAccessToken = require('./functions');
const port = 8080;

// middleware
app.use(express.json());
app.use(cors());
const multer = require('multer')
const path = require('path');
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
  }
})

const storageMoments = multer.diskStorage({
  destination: 'moments/',
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
  }
})

const uploadMoments = multer({ storage: storageMoments });

const upload = multer({ storage: storage });

function convertToLocalTimezone(array) {
  return array.map((item) => {
    if (Array.isArray(item)) {
      return convertToLocalTimezone(item);
    } else if (item.created_at) {
      const localDate = new Date(item.created_at).toLocaleString();
      return { ...item, created_at: localDate };
    } else {
      return item;
    }
  });
}
function convertToLocalTime(array) {
  return array.map(obj => {
    const utcTimestamp = new Date(obj.created_at);
    const localTimestamp = utcTimestamp.toLocaleString();
    return { ...obj, created_at: localTimestamp };
  });
}


function separateArrayByDate(arr) {
  let result = [];
  let tempDict = {};

  for (let i = 0; i < arr?.length; i++) {
    const item = arr[i];

    if (Array.isArray(item)) {
      let tempArr = [];

      for (let j = 0; j < item?.length; j++) {
        const obj = item[j];
        const created_at = obj.created_at;
        const day = created_at.split(",")[0].trim();

        if (!tempDict[day]) {
          tempDict[day] = [];
        }

        tempDict[day].push(obj);
      }

      tempArr = Object.values(tempDict);
      result.push(...tempArr);
      tempDict = {};
    } else {
      result.push(item);
    }
  }

  return result;
}

function getLatestObjectsPerDay(array) {
  const latestObjects = {};

  array.forEach(obj => {
    const date = new Date(obj.created_at).toLocaleDateString();
    if (!latestObjects[date] || new Date(obj.created_at) > new Date(latestObjects[date].created_at)) {
      latestObjects[date] = obj;
    }
  });

  return Object.values(latestObjects);
}

function compareCreatedAt(a, b) {
  const dateA = Array.isArray(a) ? new Date(a[0].created_at) : new Date(a.created_at);
  const dateB = Array.isArray(b) ? new Date(b[0].created_at) : new Date(b.created_at);
  return dateB - dateA;
}

function convertUtcTimestamp(utcTimestamp) {
  const formattedTimestamp = moment.utc(utcTimestamp).local().format('M/D/YYYY, h:mm:ss A');
  return formattedTimestamp;
}

app.use('/uploads', express.static(__dirname + '/uploads'));
app.use('/moments', express.static(__dirname + '/moments'));

// routes

// privacy policy
app.get('/privacy-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy-policy.html'));
});

app.get('/', (req, res) => {
  res.send('Welcome to the server');
});

// verify if email exits or not
app.get('/api/users/verify-email', async (req, res) => {
  const email = req.query.email;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows?.length > 0) {
      return res.status(409).json({ status: 409, message: 'Email already exists, Please try logging In.' });
    } else {
      return res.status(200).json({ status: 200, message: 'Email does not exists' });
    }
  } catch (err) {
    return res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});



// verify if username exits or not-------------------------------------------------------------------------------
app.get('/api/users/verify-username', async (req, res) => {
  const username = req.query.username;

  if (username.length < 3) {
    return res.status(409).json({ status: 409, message: 'Username must be greater than 2 characters' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      return res.status(409).json({ status: 409, message: 'Username already exists, Please try another one.' });
    } else {
      return res.status(200).json({ status: 200, message: 'Username does not exists' });
    }
  } catch (err) {
    return res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// create account-------------------------------------------------------------------------------
app.post('/api/users/create-account', async (req, res) => {
  const { name, email, username, password, dob } = req.body;

  try {
    bcrypt.genSalt(10, function (err, salt) {
      bcrypt.hash(password, salt, async function (err, hash) {
        try {

          // check if email already exists
          const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
          if (result.rows?.length > 0) {
            return res.status(409).json({ status: 409, message: 'Email already exists, Please try logging In.' });
          }

          const newUser = await pool.query(
            'INSERT INTO users (name, email, created_at, dob, password, username) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, email, new Date(), dob, hash, username]
          );
          const token = generateAccessToken(newUser.rows[0]);
          await pool.query('INSERT INTO user_sessions (user_id, token, created_at) VALUES ($1, $2, $3) RETURNING *', [newUser.rows[0].id, token, new Date()]);
          await pool.query('INSERT INTO user_profile (user_id, created_at) VALUES ($1, $2) RETURNING *', [newUser.rows[0].id, new Date()]);
          await pool.query('INSERT INTO user_mood (user_id, mood, created_at) VALUES ($1, $2, $3) RETURNING *', [newUser.rows[0].id, '', new Date()]);

          delete newUser.rows[0].password;
          newUser.rows[0].token = token;
          res.status(200).json({ status: 200, data: newUser.rows[0] });
        } catch (err) {
          res.status(500).json({ status: 500, message: 'Internal Server Error' });
        }
      });
    });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});

// Login-------------------------------------------------------------------------------
app.get('/api/users/login', async (req, res) => {

  const { email, password } = req.query;

  const userInfo = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (userInfo.rows.length !== 0) {
    const verifyCred = await bcrypt.compare(password, userInfo.rows[0].password);
    if (verifyCred) {
      const token = generateAccessToken(userInfo.rows[0]);
      const session = await pool.query('INSERT INTO user_sessions (user_id, token, created_at) VALUES ($1, $2, $3) RETURNING *', [userInfo.rows[0].id, token, new Date()]);
      if (session.rows.length === 0) {
        return res.status(500).json({ status: 500, message: 'Internal Server Error' });
      }
      delete userInfo.rows[0].password;
      userInfo.rows[0].token = token;
      return res.status(200).json({
        status: 200, data: userInfo.rows[0], message: 'Login Successful'
      });
    }
  }
  return res.status(401).json({ status: 401, message: 'Invalid Credentials' });
});

async function checkToken(req, res, next) {
  const token = req.headers.authorization;
  try {
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    if (session.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'Session not found' });
    }
  } catch (err) {
    return res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
  if (token === undefined) {
    return res.status(401).json({ status: 401, message: 'Unauthorized' });
  }
  next();
}

// generate otp and send it in user's email and store it in user_otp table-------------------------------------------------------------------------------
app.post('/api/users/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'User not found' });
    }
    await pool.query('DELETE FROM user_otp WHERE user_id = $1', [user.rows[0].id]);
    const otp = Math.floor(100000 + Math.random() * 900000);
    const otpInfo = await pool.query('INSERT INTO user_otp (user_id, otp) VALUES ($1, $2) RETURNING *', [user.rows[0].id, otp]);
    if (otpInfo.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    } else {
      const transporter = nodemailer.createTransport({
        host: 'smtppro.zoho.in',
        port: 587,
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD
        }
      });

      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Reset your yeet account password',
        text: `Use ${otp} to reset password for your yeet account.`,
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          return res.status(500).json({ status: 500, message: 'Internal Server Error' });
        }
        res.status(200).json({ status: 200, message: 'OTP sent to your email' });
      });
    }

  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});

// verify otp-------------------------------------------------------------------------------
app.post('/api/users/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'User not found' });
    }
    const otpInfo = await pool.query('SELECT * FROM user_otp WHERE user_id = $1', [user.rows[0].id]);
    if (otpInfo.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'OTP not found' });
    }
    if (otpInfo.rows[0].otp === otp) {
      return res.status(200).json({ status: 200, message: 'OTP verified' });
    } else {
      return res.status(200).json({ status: 401, message: 'You have entered an invalid OTP' });
    }
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});

// reset password-------------------------------------------------------------------------------
app.post('/api/users/reset-password', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'User not found' });
    }
    await pool.query('DELETE FROM user_otp WHERE user_id = $1', [user.rows[0].id]);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const updateInfo = await pool.query('UPDATE users SET password = $1 WHERE email = $2 RETURNING *', [hashedPassword, email]);
    if (updateInfo.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    }
    res.status(200).json({ status: 200, message: 'Password reset successful' });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});



// Logout-------------------------------------------------------------------------------
app.delete('/api/users/logout', checkToken, async (req, res) => {

  const token = req.headers.authorization;

  try {
    const session = await pool.query('DELETE FROM user_sessions WHERE token = $1 RETURNING *', [token]);
    if (session.rowCount === 0) {
      return res.status(404).json({ status: 404, message: 'Session not found' });
    }
    res.status(200).json({ status: 200, message: 'Logout Successful' });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});


// Get User Profile-------------------------------------------------------------------------------
app.get('/api/users/profile', checkToken, async (req, res) => {
  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]).then(async (result) => {
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [result?.rows[0]?.user_id]);
      const friends = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 OR req_to_id = $1) AND (status = $2)', [result?.rows[0]?.user_id, "accepted"]);

      if (profile.rows.length === 0) {
        return res.status(404).json({ status: 404, message: 'Profile not found', data: null });
      } else {
        res.status(200).json({ status: 200, data: { ...profile.rows[0], totalFriends: friends.rows.length } });
      }
    }).catch((err) => {
      res.status(500).json({ status: 500, message: 'Internal Server Error' });
    });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// Update User Profile Picture-------------------------------------------------------------------------------
app.put('/api/users/dp', upload.single('profile_pic'), async (req, res) => {
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    // Retrieve the previous profile picture path from the database
    const prevProfile = await pool.query('SELECT profile_pic FROM user_profile WHERE user_id = $1', [session.rows[0].user_id]);

    // Delete the previous image if it exists
    if (prevProfile.rows[0]?.profile_pic) {
      const prevImagePath = prevProfile.rows[0].profile_pic.replace('/uploads/', '');
      const prevImageFilePath = `uploads/${prevImagePath}`;
      fs.unlinkSync(prevImageFilePath);
    }
    const profile = await pool.query('UPDATE user_profile SET profile_pic = $1 WHERE user_id = $2 RETURNING *', [`/uploads/${req.file.filename}`, session.rows[0].user_id]);
    if (profile.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    }
    res.status(200).json({ status: 200, data: profile.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// Update User Profile-------------------------------------------------------------------------------
app.put('/api/users/profile-update', checkToken, async (req, res) => {
  const { bio, theme, is_public } = req.body;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const profile = await pool.query('UPDATE user_profile SET bio = $1, theme = $2, is_public = $3 WHERE user_id = $4 RETURNING *', [bio, theme, is_public, session.rows[0].user_id]);
    if (profile.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    }
    res.status(200).json({ status: 200, data: profile.rows[0] });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});


// post moments------------------------------------------------------------------------------- 
app.post('/api/users/post_moments', uploadMoments.single('moment'), checkToken, async (req, res) => {
  const token = req.headers.authorization;
  const { caption } = req.query;
  const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
  const moment = await pool.query('INSERT INTO user_posts_moments (user_id, moment, created_at, caption) VALUES ($1, $2, $3, $4) RETURNING *', [session.rows[0].user_id, `/moments/${req.file.filename}`, new Date(), caption]);
  if (moment.rows.length === 0) {
    return res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
  res.status(200).json({ status: 200, data: moment.rows[0] });
});


// Update mood-------------------------------------------------------------------------------
app.put('/api/users/update_mood', checkToken, async (req, res) => {
  const { text } = req.body;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const profile = await pool.query('UPDATE user_mood SET mood = $1, created_at = $2 WHERE user_id = $3 RETURNING *', [text, new Date(), session?.rows[0]?.user_id]);
    if (profile.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    }
    res.status(200).json({ status: 200, data: profile.rows[0] });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});

// get mood-------------------------------------------------------------------------------
app.get('/api/users/get_mood', checkToken, async (req, res) => {
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const profile = await pool.query('SELECT * FROM user_mood WHERE user_id = $1', [session.rows[0].user_id]);
    if (profile.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'Profile not found', data: null });
    } else {
      // if mood created_at is more than 1 day old, return null
      const today = new Date();
      const created_at = new Date(profile.rows[0].created_at);
      const diffTime = Math.abs(today - created_at);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      if (diffDays > 1) {
        return res.status(200).json({ status: 200, data: null });
      }
      res.status(200).json({ status: 200, data: profile.rows[0] });
    }
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// post memos-------------------------------------------------------------------------------
app.post('/api/users/post_memos', checkToken, async (req, res) => {
  const { Memo } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const profile = await pool.query('INSERT INTO user_posts_memos (user_id, memo) VALUES ($1, $2) RETURNING *', [session.rows[0].user_id, Memo]);
    if (profile.rows.length === 0) {
      return res.status(500).json({ status: 500, message: 'Internal Server Error' });
    }
    res.status(200).json({ status: 200, data: profile.rows[0] });
  } catch (err) {
    res.status(400).json({ status: 400, message: 'Bad Request' });
  }
});

// get user memos-------------------------------------------------------------------------------
app.get('/api/users/get_memos', checkToken, async (req, res) => {
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const memo = await pool.query('SELECT * FROM user_posts_memos WHERE user_id = $1', [session.rows[0].user_id]);
    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [session.rows[0].user_id]);
    if (memo.rows.length === 0 && profile.rows.length === 0) {
      return res.status(404).json({ status: 404, message: 'Profile not found', data: null });
    } else {
      let data = {
        profile: profile.rows[0],
        memo: memo.rows
      }
      res.status(200).json({ status: 200, data: data });
    }
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// api to search for users using name or username------------------------------------------------
app.get('/api/users/search', checkToken, async (req, res) => {
  const { search, offset } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });
    const users = await pool.query('SELECT * FROM users WHERE (name ILIKE $1 OR username ILIKE $1) AND id != $2 OFFSET $3 LIMIT $4',
      [`%${search}%`, session.rows[0].user_id, offset, 20]);

    // maps users.rows to fetch from user_profile table user details and save it in data
    const data = await Promise.all(users.rows.map(async (user) => {
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [user.id]);
      return { id: user?.id, name: user?.name, username: user?.username, profile_pic: profile?.rows[0]?.profile_pic };
    }));

    // Select all blocked users
    const blockedUsers = await pool.query('SELECT blocked_user_id FROM blocked_users WHERE user_id = $1', [session.rows[0].user_id]);
    const blockedUsers2 = await pool.query('SELECT user_id FROM blocked_users WHERE blocked_user_id = $1', [session.rows[0].user_id]);

    const blockedUserArray = blockedUsers.rows.map((user) => user.blocked_user_id);
    const blockedUserArray2 = blockedUsers2.rows.map((user) => user.user_id);

    // remove blocked users from data
    const filteredData = data.filter((user) => ![...blockedUserArray, ...blockedUserArray2].includes(user.id));

    res.status(200).json({ status: 200, data: filteredData });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// api to get user profile details------------------------------------------------
app.get('/api/users/other_profile', checkToken, async (req, res) => {
  const { userId } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    // check if user is trying to access other user profile
    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [userId]);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    // get mood
    const mood = await pool.query('SELECT * FROM user_mood WHERE user_id = $1', [userId]);
    // get total friends
    const friends = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 OR req_to_id = $1) AND (status = $2)', [userId, "accepted"]);
    delete user.rows[0].password;

    if (!profile.rows.length || !user.rows.length)
      return res.status(404).json({ status: 404, message: 'Profile not found' });
    else
      return res.status(200).json({
        status: 200, data: {
          ...profile.rows[0], ...user.rows[0],
          mood: mood.rows[0]?.mood ? mood.rows[0]?.mood : null, totalFriends: friends.rows.length
        }
      });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// Store friend request------------------------------------------------
app.post('/api/users/friend_request', checkToken, async (req, res) => {
  const { userId } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });
    const user_req = await pool.query('INSERT INTO friends_requests (req_by_id, req_to_id, status, created_at) VALUES ($1, $2, $3, $4) RETURNING *', [session.rows[0].user_id, userId, 'pending', new Date()]);
    if (!user_req.rows.length) return res.status(404).json({ status: 404, message: 'Profile not found' });
    else return res.status(200).json({ status: 200, data: user_req.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// get request status of friend request------------------------------------------------
app.get('/api/users/friend_request_status', checkToken, async (req, res) => {
  const { userId } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    const user_req = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 AND req_to_id = $2) OR (req_by_id = $2 AND req_to_id = $1)', [session.rows[0].user_id, userId]);
    if (!user_req.rows.length) return res.status(404).json({ status: 404, message: 'Profile not found' });
    else return res.status(200).json({ status: 200, data: user_req.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// cancel friend request----------------------------------------------------------------
app.delete('/api/users/cancel_friend_request', checkToken, async (req, res) => {
  const { userId } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    const user_req = await pool.query('DELETE FROM friends_requests WHERE (req_by_id = $1 AND req_to_id = $2) OR (req_by_id = $2 AND req_to_id = $1)', [session.rows[0].user_id, userId]);
    if (!user_req.rows.length) return res.status(200).json({ status: 200, message: 'deleted successfully' });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// accept friend request----------------------------------------------------------------
app.put('/api/users/accept_friend_request', checkToken, async (req, res) => {
  const { userId } = req.query;
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    const user_req = await pool.query('UPDATE friends_requests SET status = $1 WHERE (req_by_id = $2 AND req_to_id = $3) OR (req_by_id = $3 AND req_to_id = $2) RETURNING *', ['accepted', session.rows[0].user_id, userId]);
    if (!user_req.rows.length) return res.status(404).json({ status: 404, message: 'Profile not found' });
    else return res.status(200).json({ status: 200, data: user_req.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// get pending freinds request list------------------------------------------------
app.get('/api/users/notify_pending_friends_request', checkToken, async (req, res) => {
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    const user_req = await pool.query('SELECT * FROM friends_requests WHERE req_to_id = $1 AND status = $2', [session.rows[0].user_id, 'pending']);
    if (!user_req.rows.length) return res.status(404).json({ status: 404, message: 'Profile not found' });

    else {
      // get user name and profile image
      const data = await Promise.all(user_req.rows.map(async (item) => {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [item.req_by_id]);
        const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [item.req_by_id]);
        return { ...item, name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic };
      }));
      return res.status(200).json({ status: 200, data: data });
    }
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// get friends moods----------------------------------------------------------------
app.get('/api/users/friends_moods', checkToken, async (req, res) => {
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    // get friends list
    const friends = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 OR req_to_id = $1) AND status = $2', [session.rows[0].user_id, 'accepted']);
    if (!friends.rows.length) return res.status(404).json({ status: 404, message: 'No friends found' });
    // get friends moods
    const friends_moods = await Promise.all(friends.rows.map(async (item) => {
      const mood = await pool.query('SELECT * FROM user_mood WHERE user_id = $1', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id]);
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id]);
      return { theme: profile?.rows[0]?.theme, userID: user?.rows[0]?.id, time: mood?.rows[0].created_at, mood: mood?.rows[0].mood, name: user?.rows[0].name, profile_pic: profile?.rows[0]?.profile_pic };
    }));
    // Sort the array by the 'time' property in descending order
    const sortedData = friends_moods.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    // if mood created_at is more than 1 day old then return empty mood
    // const finalData = sortedData.forEach((item) => {
    //   const diff = moment.utc(new Date()).diff(moment.utc(item.created_at), 'days');
    //   if (diff > 1) item.mood = '';
    // });

    return res.status(200).json({ status: 200, data: sortedData.filter(item => item.mood !== '') });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});



// get feed data from user_posts_memos and user_posts_moments of friends and user itself arranged by time
app.get('/api/users/feed', checkToken, async (req, res) => {
  const currentDate = moment.utc(new Date()).local().format("YYYY-MM-DD");
  const prevDate = moment.utc().local().subtract(1, 'day').format("YYYY-MM-DD");
  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // check if user is authenticated
    if (!session.rows.length) return res.status(404).json({ status: 404, message: 'Authentication fail' });

    // get friends list
    const friends = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 OR req_to_id = $1) AND status = $2', [session.rows[0].user_id, 'accepted']);
    // get friends posts
    const friends_posts = await Promise.all(friends.rows.map(async (item) => {
      const posts_memos = await pool.query('SELECT * FROM user_posts_memos WHERE user_id = $1 AND DATE(created_at) BETWEEN $2 AND $3 ORDER BY id DESC', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id, prevDate, currentDate]);
      const posts_moments = await pool.query('SELECT * FROM user_posts_moments WHERE user_id = $1 AND DATE(created_at) BETWEEN $2 AND $3 ORDER BY id DESC', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id, prevDate, currentDate]);
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [session.rows[0].user_id === item.req_by_id ? item.req_to_id : item.req_by_id]);
      const dataMemos = [
        ...posts_memos?.rows?.map(item => ({ ...item, type: 'memo', name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, theme: profile.rows[0].theme })),
      ]
      const dataMoments = posts_moments?.rows?.map(item => ({ ...item, type: 'moment', name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic }));
      return [...dataMemos, dataMoments];
    }));

    // get user memos and moments
    const user_posts_memos = await pool.query('SELECT * FROM user_posts_memos WHERE user_id = $1 AND DATE(created_at)  BETWEEN $2 AND $3 ORDER BY id DESC', [session.rows[0].user_id, prevDate, currentDate]);
    const user_posts_moments = await pool.query('SELECT * FROM user_posts_moments WHERE user_id = $1 AND DATE(created_at)  BETWEEN $2 AND $3 ORDER BY id DESC', [session.rows[0].user_id, prevDate, currentDate]);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [session.rows[0].user_id]);
    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [session.rows[0].user_id]);

    const dataMemos = [
      ...user_posts_memos?.rows?.map(item => ({ ...item, type: 'memo', name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, theme: profile.rows[0].theme })),
    ]
    const dataMoments = [
      ...user_posts_moments?.rows?.map(item => ({ ...item, type: 'moment', name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic })),
    ]

    const data = [...dataMemos, dataMoments, ...friends_posts.flat()];

    const modifiedData = separateArrayByDate(convertToLocalTimezone(data));

    return res.status(200).json({ status: 200, data: modifiedData.sort(compareCreatedAt) });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});



// Get moments and memos of user for profile page moments clubbed by same date--------------------------------------------
app.get('/api/users/user_profile_posts', checkToken, async (req, res) => {

  const userId = req.query.userId;

  try {
    // get all memos of the user as array of objects
    const user_posts_memos = await pool.query('SELECT * FROM user_posts_memos WHERE user_id = $1 ORDER BY id DESC', [userId]);

    // get last moment from each day of the user as array of objects
    const user_posts_moments = await pool.query('SELECT * FROM user_posts_moments WHERE user_id = $1 ORDER BY id DESC', [userId]);
    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [userId]);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const localTimeMoments = getLatestObjectsPerDay(convertToLocalTime(user_posts_moments.rows));
    const localTimeMemos = convertToLocalTime(user_posts_memos.rows);

    if (!user_posts_memos.rows.length && !user_posts_moments.rows.length)
      return res.status(404).json({ status: 404, message: 'No data found' });

    return res.status(200).json({
      status: 200, data: {
        memos: localTimeMemos.map(item => ({
          ...item,
          profile_pic: profile?.rows?.[0]?.profile_pic,
          theme: profile?.rows?.[0]?.theme,
          name: user?.rows?.[0]?.name,
        })), moments: localTimeMoments
      }
    });

  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// get moments as per that day and userID--------------------------------------------------------------------------------
app.get('/api/users/user_profile_posts_moments', checkToken, async (req, res) => {

  const userId = req.query.userId;
  const date = req.query.date;
  try {
    // get all memos of the user as array of objects
    const user_posts_moments = await pool.query('SELECT * FROM user_posts_moments WHERE user_id = $1 AND DATE(created_at) = $2 ORDER BY id DESC', [userId, date]);

    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [userId]);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (!user_posts_moments.rows.length || !profile.rows.length)
      return res.status(404).json({ status: 404, message: 'No data found' });

    const modifiedData = user_posts_moments.rows.map(item => ({
      ...item,
      date: item?.created_at,
      profile_pic: profile.rows[0].profile_pic,
      name: user.rows[0].name,
    })
    );

    return res.status(200).json({
      status: 200, data: modifiedData
    });

  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// like posts api for moments and memos DB schema-------------------------------------------------------------------------
app.post('/api/users/like_post', checkToken, async (req, res) => {
  const { postId, postType } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const like = await pool.query('INSERT INTO user_posts_likes (user_id, post_id, post_type) VALUES ($1, $2, $3) RETURNING *', [session.rows[0].user_id, postId, postType]);
    return res.status(200).json({ status: 200, message: 'Post liked successfully', data: like.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// is post liked api for moments and memos and total likes of postId--------------------------------------------------------
app.get('/api/users/is_post_liked', checkToken, async (req, res) => {
  const { postId, postType } = req.query;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const isLiked = await pool.query('SELECT * FROM user_posts_likes WHERE user_id = $1 AND post_id = $2 AND post_type = $3', [session.rows[0].user_id, postId, postType]);
    const likedByUsers = await pool.query('SELECT * FROM user_posts_likes WHERE post_id = $1 AND post_type = $2', [postId, postType]);
    // get name and profile pic of users bu user_id in likedbyusers
    const NameProfile = await Promise.all(likedByUsers.rows.map(async (item) => {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [item.user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [item.user_id]);
      return { name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, id: item.user_id };
    }));
    const totalLikes = await pool.query('SELECT COUNT(*) FROM user_posts_likes WHERE post_id = $1 AND post_type = $2', [postId, postType]);
    return res.status(200).json({ status: 200, message: 'Post liked successfully', data: { isLiked: isLiked.rows.length > 0, totalLikes: totalLikes.rows[0].count, likedByUsers: NameProfile } });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// remove like posts api for moments and memos DB schema-------------------------------------------------------------------------
app.delete('/api/users/remove_like_post', checkToken, async (req, res) => {
  const { postId, postType } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const like = await pool.query('DELETE FROM user_posts_likes WHERE user_id = $1 AND post_id = $2 AND post_type = $3 RETURNING *', [session.rows[0].user_id, postId, postType]);
    return res.status(200).json({ status: 200, message: 'Post unliked successfully', data: like.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// add comment api for moments and memos DB schema-------------------------------------------------------------------------
app.post('/api/users/add_comment', checkToken, async (req, res) => {
  const { postId, postType, comment } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const commentAdd = await pool.query('INSERT INTO user_posts_comments (user_id, post_id, post_type, comment, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *', [session.rows[0].user_id, postId, postType, comment, new Date()]);
    return res.status(200).json({ status: 200, message: 'Comment added successfully', data: commentAdd.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

const getNamePic = async (arr) => {
  const newArr = [];
  for (let i = 0; i < arr.length; i++) {
    const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [arr[i].user_id]);
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [arr[i].user_id]);
    newArr.push({
      ...arr[i],
      profile_pic: profile.rows[0].profile_pic,
      name: user.rows[0].name,
      user_id: user.rows[0].id,
      date: arr[i]?.created_at,
    });
  }
  return newArr;
}


// get comments api for moments and memos DB schema-------------------------------------------------------------------------
app.get('/api/users/get_comments', checkToken, async (req, res) => {
  const { postId, postType } = req.query;

  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const comments = await pool.query('SELECT * FROM user_posts_comments WHERE post_id = $1 AND post_type = $2', [postId, postType]);
    const commentsWithUser = await getNamePic(comments.rows);

    // sort comments from older to newer created_at


    return res.status(200).json({ status: 200, message: 'Comments fetched successfully', data: commentsWithUser.sort((a, b) => new Date(a.created_at) - new Date(b.created_at)) });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// api to add notification for replied comments in db-------------------------------------------------------------------------
app.post('/api/users/add_replied_comment_notification', checkToken, async (req, res) => {
  const { commentUserId, repliedUserId, postId, postType } = req.body;

  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    const notification = await pool.query('INSERT INTO replied_comments (comment_user_id, replied_user_id, post_id, post_type, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *', [commentUserId, repliedUserId, postId, postType, new Date()]);

    return res.status(200).json({ status: 200, message: 'Notification added successfully', data: notification.rows[0] });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});


// api to delete moment along with all its comments and likes-------------------------------------------------------------------------
app.delete('/api/users/delete_moment', checkToken, async (req, res) => {
  const { momentId } = req.query;

  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    await pool.query('DELETE FROM user_posts_likes WHERE post_id = $1 AND post_type = $2', [momentId, 'moment']);
    await pool.query('DELETE FROM user_posts_comments WHERE post_id = $1 AND post_type = $2', [momentId, 'moment']);
    await pool.query('DELETE FROM user_posts_moments WHERE id = $1', [momentId]);

    return res.status(200).json({ status: 200, message: 'Moment deleted successfully' });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// api to delete memo along with all its comments and likes-------------------------------------------------------------------------
app.delete('/api/users/delete_memo', checkToken, async (req, res) => {
  const { memoId } = req.query;

  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    await pool.query('DELETE FROM user_posts_likes WHERE post_id = $1 AND post_type = $2', [memoId, 'memo']);
    await pool.query('DELETE FROM user_posts_comments WHERE post_id = $1 AND post_type = $2', [memoId, 'memo']);
    await pool.query('DELETE FROM user_posts_memos WHERE id = $1', [memoId]);

    return res.status(200).json({ status: 200, message: 'Memo deleted successfully' });
  } catch (err) {
    res.status(500).json({ status: 500, message: 'Internal Server Error' });
  }
});

// get List of friends by user id-------------------------------------------------------------------------
app.get('/api/users/get_friends', checkToken, async (req, res) => {
  const { userId } = req.query;

  try {
    const allFriends = await pool.query('SELECT * FROM friends_requests WHERE (req_by_id = $1 AND status = $2) OR (req_to_id = $1 AND status = $2)', [userId, 'accepted']);

    const data = await Promise.all(allFriends.rows.map(async (item) => {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId == item?.req_by_id ? item?.req_to_id : item?.req_by_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [userId == item?.req_by_id ? item?.req_to_id : item?.req_by_id]);
      return { name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, id: user.rows[0].id };
    }))

    return res.status(200).json({ status: 200, message: 'Friends fetched successfully', data });
  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})

// report user-------------------------------------------------------------------------
app.post('/api/users/report_user', checkToken, async (req, res) => {
  const { reportedUserId, ReportReason } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    await pool.query('INSERT INTO user_reports (user_id, reported_user_id, reason, created_at) VALUES ($1, $2, $3, $4)', [session.rows[0].user_id, reportedUserId, ReportReason, new Date()]);
    return res.status(200).json({ status: 200, message: 'User reported successfully' });
  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// api to get notifications where user_posts_likes is_view is false
app.get('/api/users/get_notifications', checkToken, async (req, res) => {

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    // get all memos and moments of user
    const allMemos = await pool.query('SELECT id FROM user_posts_memos WHERE user_id = $1', [session.rows[0].user_id]);
    const allMoments = await pool.query('SELECT id FROM user_posts_moments WHERE user_id = $1', [session.rows[0].user_id]);
    const memoArr = [...allMemos.rows.map(item => item.id)];
    const momentArr = [...allMoments.rows.map(item => item.id)];


    // select all from user_posts_likes where post_id in (memoArr, momentArr) and user_id is not session user id
    const MemoLikes = await pool.query('SELECT * FROM user_posts_likes WHERE post_id = ANY($1) AND user_id != $2', [memoArr, session.rows[0].user_id]);
    const MomentLikes = await pool.query('SELECT * FROM user_posts_likes WHERE post_id = ANY($1) AND user_id != $2', [momentArr, session.rows[0].user_id]);

    // select all from user_posts_comments where post_id in (memoArr, momentArr) and user_id is not session user id
    const MemoComments = await pool.query('SELECT * FROM user_posts_comments WHERE post_id = ANY($1) AND user_id != $2', [memoArr, session.rows[0].user_id]);
    const MomentComments = await pool.query('SELECT * FROM user_posts_comments WHERE post_id = ANY($1) AND user_id != $2', [momentArr, session.rows[0].user_id]);

    // make MemoLikes and MomentLikes a single array of object arranged as per created_at
    const allLikes = [...MemoLikes.rows, ...MomentLikes.rows].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    // make MemoComments and MomentComments a single array of object arranged as per created_at
    const allComments = [...MemoComments.rows, ...MomentComments.rows].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));


    // get profile pic and name of user who liked the post
    const data = await Promise.all(allLikes.map(async (item) => {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [item.user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [item.user_id]);
      return { name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, ...item, interaction_type: 'liked' };
    }))

    // get profile pic and name of user who commented on the post
    const data2 = await Promise.all(allComments.map(async (item) => {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [item.user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [item.user_id]);
      return { name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, ...item, interaction_type: 'commented' };
    }))

    // get notfication from replied_comments table where comment_user_id is session user_id
    const repliedComments = await pool.query('SELECT * FROM replied_comments WHERE replied_user_id = $1', [session.rows[0].user_id]);


    // get user name and profile pic of comment_user_id
    const data3 = await Promise.all(repliedComments.rows.map(async (item) => {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [item.comment_user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [item.comment_user_id]);
      return { name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, ...item, interaction_type: 'replied' };
    }))


    // merge data and data2 and sort as per created_at
    const finalData = [...data, ...data2, ...data3].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    // Select all blocked users
    const blockedUsers = await pool.query('SELECT blocked_user_id FROM blocked_users WHERE user_id = $1', [session.rows[0].user_id]);
    const blockedUsers2 = await pool.query('SELECT user_id FROM blocked_users WHERE blocked_user_id = $1', [session.rows[0].user_id]);

    const blockedUserArray = [...blockedUsers.rows.map((user) => user.blocked_user_id), ...blockedUsers2.rows.map((user) => user.user_id)];

    // remove blocked users from finalData
    const filteredData = finalData.filter((item) => !blockedUserArray.includes(item.user_id || item.comment_user_id || item.replied_user_id));

    return res.status(200).json({ status: 200, message: 'Notifications fetched successfully', data: filteredData });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// api to get memo or moment as per post_id----------------------------------------------
app.get('/api/users/get_memo_moment', checkToken, async (req, res) => {

  const { post_id, post_type } = req.query;


  try {
    const token = req.headers.authorization;
    await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    if (post_type === 'memo') {
      const memo = await pool.query('SELECT * FROM user_posts_memos WHERE id = $1', [post_id]);
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [memo.rows[0].user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [memo.rows[0].user_id]);

      return res.status(200).json({
        status: 200, message: 'Memo fetched successfully', data: {
          ...memo.rows[0], name: user.rows[0].name,
          profile_pic: profile.rows[0]?.profile_pic, post_type: "memo", theme: profile?.rows[0]?.theme
        }
      });
    } else if (post_type === 'moment') {
      const moment = await pool.query('SELECT * FROM user_posts_moments WHERE id = $1', [post_id]);
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [moment.rows[0].user_id]);
      const profile = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [moment.rows[0].user_id]);

      return res.status(200).json({ status: 200, message: 'Moment fetched successfully', data: { ...moment.rows[0], name: user.rows[0].name, profile_pic: profile.rows[0].profile_pic, post_type: 'moment' } });
    }

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// api to set is_view to true for a particular post in user_posts_likes and user_posts_comments----------------------------------------------
app.put('/api/users/set_is_view', checkToken, async (req, res) => {
  const { post_id, post_type, interaction_type } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    if (post_type === 'memo') {
      if (interaction_type === 'liked') {
        await pool.query('UPDATE user_posts_likes SET is_view = $1 WHERE post_id = $2 AND user_id != $3', [true, post_id, session.rows[0].user_id]);
      } else if (interaction_type === 'commented') {
        await pool.query('UPDATE user_posts_comments SET is_view = $1 WHERE post_id = $2 AND user_id != $3', [true, post_id, session.rows[0].user_id]);
      } else if (interaction_type === 'replied') {
        await pool.query('UPDATE replied_comments SET is_view = $1 WHERE post_id = $2 AND replied_user_id = $3 AND post_type = $4', [true, post_id, session.rows[0].user_id, post_type]);
      }
    } else if (post_type === 'moment') {
      if (interaction_type === 'liked') {
        await pool.query('UPDATE user_posts_likes SET is_view = $1 WHERE post_id = $2 AND user_id != $3', [true, post_id, session.rows[0].user_id]);
      } else if (interaction_type === 'commented') {
        await pool.query('UPDATE user_posts_comments SET is_view = $1 WHERE post_id = $2 AND user_id != $3', [true, post_id, session.rows[0].user_id]);
      } else if (interaction_type === 'replied') {
        await pool.query('UPDATE replied_comments SET is_view = $1 WHERE post_id = $2 AND replied_user_id = $3 AND post_type = $4', [true, post_id, session.rows[0].user_id, post_type]);
      }
    }

    return res.status(200).json({ status: 200, message: 'is_view set successfully' });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})

// api to block user----------------------------------------------
app.post('/api/users/block_user', checkToken, async (req, res) => {
  const { blocked_user_id } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);
    await pool.query('INSERT INTO blocked_users (user_id, blocked_user_id, created_at) VALUES ($1, $2, $3)', [session.rows[0].user_id, blocked_user_id, new Date()]);
    return res.status(200).json({ status: 200, message: 'User blocked successfully' });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// get list of blocked users----------------------------------------------
app.get('/api/users/get_blocked_users', checkToken, async (req, res) => {

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    const blocked_users = await pool.query('SELECT * FROM blocked_users WHERE user_id = $1', [session.rows[0].user_id]);

    // get blocked users name and profile pic
    const blocked_users_data = await Promise.all(blocked_users.rows.map(async (user) => {
      const user_data = await pool.query('SELECT * FROM users WHERE id = $1', [user.blocked_user_id]);
      const profile_data = await pool.query('SELECT * FROM user_profile WHERE user_id = $1', [user.blocked_user_id]);
      return { ...user, name: user_data.rows[0].name, profile_pic: profile_data.rows[0].profile_pic };
    }));

    return res.status(200).json({ status: 200, message: 'Blocked users fetched successfully', data: blocked_users_data });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// get list of block user by user_id----------------------------------------------
app.get('/api/users/get_blocked_users_by_user_id', checkToken, async (req, res) => {
  const { user_id } = req.query;

  try {
    const blocked_users = await pool.query('SELECT * FROM blocked_users WHERE user_id = $1', [user_id]);

    return res.status(200).json({ status: 200, message: 'Blocked users fetched successfully', data: blocked_users.rows });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})

// api to unblock user----------------------------------------------
app.delete('/api/users/unblock_user', checkToken, async (req, res) => {
  const { blocked_user_id } = req.body;

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    await pool.query('DELETE FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2', [session.rows[0].user_id, blocked_user_id]);
    return res.status(200).json({ status: 200, message: 'User unblocked successfully' });

  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})


// delete user and all its data-------------------------------------------------------------------------
app.delete('/api/users/delete_user', checkToken, async (req, res) => {

  try {
    const token = req.headers.authorization;
    const session = await pool.query('SELECT * FROM user_sessions WHERE token = $1', [token]);

    await pool.query('DELETE FROM user_posts_likes WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_posts_comments WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_posts_moments WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_posts_memos WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_mood WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_profile WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM friends_requests WHERE req_by_id = $1 OR req_to_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM users WHERE id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_otp WHERE user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM friends_requests WHERE req_by_id = $1 OR req_to_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM user_reports WHERE user_id = $1 OR reported_user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM replied_comments where comment_user_id = $1 OR replied_user_id = $1', [session.rows[0].user_id]);
    await pool.query('DELETE FROM blocked_users WHERE user_id = $1 OR blocked_user_id = $1', [session.rows[0].user_id]);

    return res.status(200).json({ status: 200, message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ status: 500, message: "Internal Server Error" })
  }
})





app.listen(port, () => console.log(`app listening on port ${port}!`));