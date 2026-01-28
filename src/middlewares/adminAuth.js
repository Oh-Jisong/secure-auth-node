const jwt = require("jsonwebtoken");

module.exports = function adminAuth(req, res, next) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ ok: false, message: "No token" });
  }

  const token = auth.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // MVP: test@example.com 만 관리자라고 가정
    if (decoded.email !== "test@example.com") {
      return res.status(403).json({ ok: false, message: "Forbidden" });
    }

    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ ok: false, message: "Invalid token" });
  }
};