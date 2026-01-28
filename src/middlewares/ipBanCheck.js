const pool = require("../db");

module.exports = async function ipBanCheck(req, res, next) {
  try {
    const ip = req.ip;

    const [rows] = await pool.query(
      `SELECT ip_address, banned_until
       FROM banned_ips
       WHERE ip_address = ?
       LIMIT 1`,
      [ip]
    );

    if (rows.length === 0) return next();

    const bannedUntil = rows[0].banned_until;
    if (!bannedUntil) {
      return res.status(403).json({ ok: false, message: "IP banned" });
    }

    const now = new Date();
    if (new Date(bannedUntil) > now) {
      return res.status(403).json({ ok: false, message: "IP banned (temporary)" });
    }

    // 밴 만료면 자동 해제(선택)
    await pool.query(`DELETE FROM banned_ips WHERE ip_address = ?`, [ip]);
    return next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
};