const jwt = require("jsonwebtoken");

module.exports = function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ ok: false, message: "Missing access token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded; // { sub, email, iat, exp }
    return next();
  } catch {
    return res.status(401).json({ ok: false, message: "Invalid or expired access token" });
  }
};