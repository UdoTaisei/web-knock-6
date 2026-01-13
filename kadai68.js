const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");

const app = express();
app.use(express.json());

const path = require("path");
app.use(express.static(path.join(__dirname, "public")));

//DB接続
const db = new sqlite3.Database("auth.db");

//セッション設定
app.use(
  session({
    secret: "super-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax"
    },
  })
);

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

//ログインAPI
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username と password は必須です" });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err) return res.status(500).json({ error: "DBエラー" });
      if (!user) return res.status(401).json({ error: "存在しないユーザ" });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: "パスワードが違います" });

      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({
        message: "ログイン成功",
        userId: user.id,
        username: user.username,
      });
    });
  } catch (e) {
    res.status(500).json({ error: "サーバ内部エラー" });
  }
});

app.get("/private", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "private.html"));
});

//ログイン確認
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "ログインしていません" });
  }
  next();
}

//ログイン確認API
app.get("/loginstate", requireLogin, (req, res) => {
  res.json({
    userId: req.session.userId,
    username: req.session.username,
  });
});


//ログアウトAPI
app.post("/logout", requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "ログアウト" });
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000/login");
});
