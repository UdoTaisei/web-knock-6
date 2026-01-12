const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");

const app = express();
app.use(express.json());

// ===== DB接続 =====
const db = new sqlite3.Database("auth.db");

// ===== usersテーブル作成 =====
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// ===== セッション設定 =====
app.use(
  session({
    secret: "super-secret-key", // 本番では環境変数にする
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // JSから読めない（XSS対策）
      maxAge: 1000 * 60 * 60, // 1時間
    },
  })
);

// ===== 認証済みチェック（認可） =====
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "ログインが必要です" });
  }
  next();
}

// ===== 63: ユーザ登録API =====
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "username と password は必須です" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, password_hash],
      function (err) {
        if (err) {
          return res.status(400).json({ error: "ユーザ登録失敗（username重複など）" });
        }
        res.status(201).json({
          message: "ユーザ登録成功",
          userId: this.lastID,
          username,
        });
      }
    );
  } catch (e) {
    res.status(500).json({ error: "サーバ内部エラー" });
  }
});

// ===== 64+65: ログインAPI（成功時にセッション保持） =====
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username と password は必須です" });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err) return res.status(500).json({ error: "DBエラー" });
      if (!user) return res.status(401).json({ error: "ユーザ名またはパスワードが違います" });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: "ユーザ名またはパスワードが違います" });

      // ✅ セッションにログイン情報保存
      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({
        message: "ログイン成功（セッション保存）",
        userId: user.id,
        username: user.username,
      });
    });
  } catch (e) {
    res.status(500).json({ error: "サーバ内部エラー" });
  }
});

// ===== 65: 認証済みユーザのみアクセス可能なAPI =====
app.get("/me", requireLogin, (req, res) => {
  res.json({
    message: "認証済みユーザです",
    userId: req.session.userId,
    username: req.session.username,
  });
});

// ===== ログアウトAPI（セッション破棄） =====
app.post("/logout", requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "ログアウトしました（セッション破棄）" });
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
