const express = require("express");
const router = express.Router();

const { register, login, refresh, logout } = require("../controllers/authController");

// 둘 중 하나만 쓰자. (추천: loginRateLimiter 하나로 통일)
const loginRateLimiter = require("../middlewares/loginRateLimit"); // module.exports = 함수 형태여야 함
// const { loginLimiter } = require("../middlewares/rateLimit");   // 이걸 쓰려면 export가 { loginLimiter }여야 함

const ipBanCheck = require("../middlewares/ipBanCheck"); // module.exports = 함수 형태여야 함

router.post("/register", register);

// /login 은 "딱 1번만"
router.post("/login", ipBanCheck, loginRateLimiter, login);

router.post("/refresh", refresh);
router.post("/logout", logout);

module.exports = router;