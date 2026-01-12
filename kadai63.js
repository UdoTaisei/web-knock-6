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

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
