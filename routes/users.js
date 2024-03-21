var express = require("express");
var router = express.Router();
const User = require("../models/users");
const uid2 = require("uid2");
const bcrypt = require("bcrypt");

//rout for post register and secure with token and hash
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    return res.json({ result: false, error: "user already exist" });
  }
  const hash = bcrypt.hashSync(password, 10);
  const newUser = new User({
    username,
    email,
    password: hash,
    token: uid2(32),
  });
  await newUser.save().then((newUser) => {
    res.json({ result: true, token: newUser });
  });
});

//route for connect an verified
router.post("/connect", async (req, res) => {
  try {
    const data = await User.findOne({
      username: { $regex: new RegExp(req.body.username, "i") },
    });
    if (data && bcrypt.compareSync(req.body.password, data.password)) {
      res.json({ result: true, token: data.token });
    } else {
      res.json({
        result: false,
        error: "User not found or incorrect",
      });
    }
  } catch (error) {
    res.status(500).json({ result: false, error: error.message });
  }
});

//route for get all users
router.get("/", (_, res) => {
  User.find().then((data) => {
    res.json({ allusers: data });
  });
});
//route for get by token
router.get("/:token", (req, res) => {
  User.findOne(req.body.token).then((data) => {
    res.json({ data: data });
  });
});
module.exports = router;
