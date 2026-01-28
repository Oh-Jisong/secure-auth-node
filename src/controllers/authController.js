const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");

// -------------------------
// validators (MVP level)
// -------------------------
function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

// -------------------------
// jwt helpers
// -------------------------
function signAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m",
  });
}

function signRefreshToken(payload, jti) {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d",
    jwtid: jti,
  });
}


// -------------------------
// audit log helper (login only)
// -------------------------
async function insertAuthLog({ email, ip, userAgent, success, failReason = null }) {
  try {
    await pool.query(
      `INSERT INTO auth_logs (email, ip_address, user_agent, success, fail_reason)
       VALUES (?, ?, ?, ?, ?)`,
      [email ?? null, ip ?? null, userAgent ?? null, success, failReason]
    );
  } catch (e) {
    // 로깅 실패가 인증 기능을 깨면 안 됨
    console.error("auth_logs insert failed:", e?.message ?? e);
  }
}

// -------------------------
// register
// -------------------------
exports.register = async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, message: "Invalid email" });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ ok: false, message: "Password must be at least 8 characters" });
    }

    const [exists] = await pool.query("SELECT id FROM users WHERE email = ? LIMIT 1", [email]);
    if (exists.length > 0) {
      return res.status(409).json({ ok: false, message: "Email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, passwordHash]
    );

    return res.status(201).json({
      ok: true,
      user: { id: result.insertId, email },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
};

// -------------------------
// login (lockout + audit logs)
// -------------------------
exports.login = async (req, res) => {
  try {
    const ip = req.ip;
    const userAgent = req.headers["user-agent"];

    const { email, password } = req.body ?? {};

    // (선택) 입력 검증: 존재 유추 방지 위해 메시지는 동일하게 갈 거라
    // 검증 실패도 Invalid credentials로 통일해도 되지만,
    // 지금은 최소한의 형태만 유지.
    if (!isValidEmail(email) || typeof password !== "string") {
      await insertAuthLog({
        email,
        ip,
        userAgent,
        success: false,
        failReason: "INVALID_INPUT",
      });
      return res.status(401).json({ ok: false, message: "Invalid credentials" });
    }

    const [rows] = await pool.query(
      "SELECT id, email, password_hash, login_fail_count, locked_until FROM users WHERE email = ? LIMIT 1",
      [email]
    );

    // 존재 여부 숨김(계정 유추 방지)
    if (rows.length === 0) {
      await insertAuthLog({
        email,
        ip,
        userAgent,
        success: false,
        failReason: "INVALID_CREDENTIALS",
      });
      return res.status(401).json({ ok: false, message: "Invalid credentials" });
    }

    const user = rows[0];

    // 1) 잠금 상태 체크 + 만료 시 자동 해제(DB 정리)
    if (user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      const now = new Date();

      if (lockedUntil > now) {
        await insertAuthLog({
          email,
          ip,
          userAgent,
          success: false,
          failReason: "ACCOUNT_LOCKED",
        });
        return res.status(423).json({
          ok: false,
          message: "Account locked. Try again later.",
        });
      }

      // 잠금 만료됨 -> DB 정리
      await pool.query("UPDATE users SET login_fail_count = 0, locked_until = NULL WHERE id = ?", [
        user.id,
      ]);
      user.login_fail_count = 0;
      user.locked_until = null;
    }

    // 2) 비밀번호 검증
    const ok = await bcrypt.compare(password, user.password_hash);

    const MAX_FAILS = Number(process.env.MAX_LOGIN_FAILS || 5);
    const LOCK_MINUTES = Number(process.env.LOCK_MINUTES || 10);

    if (!ok) {
      const nextFail = (user.login_fail_count || 0) + 1;

      if (nextFail >= MAX_FAILS) {
        await pool.query(
          "UPDATE users SET login_fail_count = ?, locked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE id = ?",
          [nextFail, LOCK_MINUTES, user.id]
        );
      } else {
        await pool.query("UPDATE users SET login_fail_count = ? WHERE id = ?", [nextFail, user.id]);
      }

      await insertAuthLog({
        email,
        ip,
        userAgent,
        success: false,
        failReason: "INVALID_CREDENTIALS",
      });

      return res.status(401).json({ ok: false, message: "Invalid credentials" });
    }

    // 3) 로그인 성공 -> 실패 카운트/잠금 초기화
    await pool.query(
      "UPDATE users SET login_fail_count = 0, locked_until = NULL, last_login_at = NOW() WHERE id = ?",
      [user.id]
    );

    // 4) 토큰 발급 + refresh 저장
    const payload = { sub: String(user.id), email: user.email };
    const accessToken = signAccessToken(payload);
    
    // refresh 회전용 jti
    const refreshJti = crypto.randomUUID();
    const refreshToken = signRefreshToken(payload, refreshJti);

    const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

    await pool.query(
      "UPDATE users SET refresh_token_hash = ?, refresh_jti = ? WHERE id = ?",
      [refreshTokenHash, refreshJti, user.id]
    );
    
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",          // refresh도 logout도 일관되게 '/'
    });

return res.json({
  ok: true,
  accessToken,
  user: { id: user.id, email: user.email }
});


    // refresh token: HttpOnly cookie
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: false, // production(HTTPS)에서는 true 권장 (README에 명시할 것)
      sameSite: "lax",
      path: "/", // PowerShell/WebSession 테스트 안정성
    });

    await insertAuthLog({
      email,
      ip,
      userAgent,
      success: true,
      failReason: null,
    });

    return res.json({
      ok: true,
      accessToken,
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
};

// -------------------------
// refresh (issues new access token)
// -------------------------
exports.refresh = async (req, res) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ ok: false, message: "No refresh token" });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(401).json({ ok: false, message: "Invalid refresh token" });
    }

    const userId = Number(decoded.sub);
    const tokenJti = decoded.jti; // jwtid로 넣었던 값이 decoded.jti 로 들어옴

    const ip = req.ip;
    const userAgent = req.headers["user-agent"];

    const [rows] = await pool.query(
      "SELECT id, email, refresh_token_hash, refresh_jti FROM users WHERE id = ? LIMIT 1",
      [userId]
    );

    if (rows.length === 0 || !rows[0].refresh_token_hash || !rows[0].refresh_jti) {
      return res.status(401).json({ ok: false, message: "Refresh not allowed" });
    }

    const user = rows[0];

    // 1) refresh 토큰 내용이 DB 해시와 맞는지 확인 (기존 방식 유지)
    const hashMatches = await bcrypt.compare(token, user.refresh_token_hash);
    if (!hashMatches) {
      // 토큰 위조/변조/다른 토큰 사용
      return res.status(401).json({ ok: false, message: "Refresh not allowed" });
    }

    // 2) jti 비교로 "재사용 공격" 감지
    // - 정상: tokenJti === user.refresh_jti
    // - 비정상: tokenJti !== user.refresh_jti (예: 예전 refresh 토큰 재사용)
    if (!tokenJti || tokenJti !== user.refresh_jti) {
      // 재사용 의심 → 즉시 폐기(강제 로그아웃)
      await pool.query(
        "UPDATE users SET refresh_token_hash = NULL, refresh_jti = NULL WHERE id = ?",
        [userId]
      );

      // (선택) 로그 남기기
      await pool.query(
        `INSERT INTO auth_logs (email, ip_address, user_agent, success, fail_reason)
         VALUES (?, ?, ?, ?, ?)`,
        [user.email, ip, userAgent, false, "REFRESH_REUSE_DETECTED"]
      );

      res.clearCookie("refresh_token", { path: "/" });
      return res.status(401).json({ ok: false, message: "Refresh not allowed" });
    }

    // 3) 정상 refresh → ROTATION: 새 refresh 발급 + DB 교체
    const payload = { sub: String(user.id), email: user.email };

    const newAccessToken = signAccessToken(payload);

    const newRefreshJti = crypto.randomUUID();
    const newRefreshToken = signRefreshToken(payload, newRefreshJti);
    const newRefreshHash = await bcrypt.hash(newRefreshToken, 12);

    await pool.query(
      "UPDATE users SET refresh_token_hash = ?, refresh_jti = ? WHERE id = ?",
      [newRefreshHash, newRefreshJti, userId]
    );

    res.cookie("refresh_token", newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
    });

    // (선택) 로그
    await pool.query(
      `INSERT INTO auth_logs (email, ip_address, user_agent, success, fail_reason)
       VALUES (?, ?, ?, ?, ?)`,
      [user.email, ip, userAgent, true, "REFRESH_ROTATED"]
    );

    return res.json({ ok: true, accessToken: newAccessToken });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
};

// -------------------------
// logout (revokes refresh token)
// -------------------------
exports.logout = async (req, res) => {
  try {
    const token = req.cookies?.refresh_token;

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        const userId = Number(decoded.sub);

        await pool.query("UPDATE users SET refresh_token_hash = NULL WHERE id = ?", [userId]);
      } catch {
        // ignore
      }
    }

    // cookie path가 "/" 이므로 clear도 "/"로 맞춰야 함
    res.clearCookie("refresh_token", { path: "/" });

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
};