const express = require("express");
const router = express.Router();
const adminAuth = require("../middlewares/adminAuth");

router.get("/auth-logs", adminAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT email, ip_address, success, fail_reason, created_at
      FROM auth_logs
      ORDER BY id DESC
      LIMIT 50
    `);

    res.json({ ok: true, logs: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});

module.exports = router;