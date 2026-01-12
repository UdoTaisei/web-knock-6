const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

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

// ===== ユーザ登録API =====
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 入力チェック
    if (!username || !password) {
      return res.status(400).json({ error: "username と password は必須です" });
    }

    // パスワードをハッシュ化
    const password_hash = await bcrypt.hash(password, 10);

    // DBに登録
    db.run(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, password_hash],
      function (err) {
        if (err) {
          // username重複など
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

// ===== 64: ログインAPI =====
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;

    // 入力チェック
    if (!username || !password) {
      return res.status(400).json({ error: "username と password は必須です" });
    }

    // ユーザ取得
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: "DBエラー" });
      }

      // usernameが存在しない
      if (!user) {
        return res.status(401).json({ error: "ユーザ名またはパスワードが違います" });
      }

      // パスワード照合（平文 vs ハッシュ）
      const ok = await bcrypt.compare(password, user.password_hash);

      // パスワード不一致
      if (!ok) {
        return res.status(401).json({ error: "ユーザ名またはパスワードが違います" });
      }

      // 成功
      return res.json({
        message: "ログイン成功",
        userId: user.id,
        username: user.username,
      });
    });
  } catch (e) {
    res.status(500).json({ error: "サーバ内部エラー" });
  }
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
