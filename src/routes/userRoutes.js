const express = require("express");
const auth = require("../middlewares/auth");

const router = express.Router();

router.get("/me", auth, (req, res) => {
  return res.json({
    ok: true,
    user: {
      id: req.user.sub,
      email: req.user.email
    }
  });
});

module.exports = router;