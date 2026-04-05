// ⚠️  DEMO FILE — this code is intentionally vulnerable
// It is never executed. Faults exist to trigger semgrep SAST rules.

const express = require('express');
const { exec } = require('child_process');
const db = require('./db');

const app = express();
app.use(express.json());

// VULN: Reflected XSS — user input rendered directly into HTML response
app.get('/greet', (req, res) => {
  res.send('<h1>Hello, ' + req.query.name + '</h1>');
});

// VULN: SQL injection — string concatenation in query
app.get('/user/:id', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query, (err, rows) => res.json(rows));
});

// VULN: Remote code execution — eval on user-supplied input
app.post('/run', (req, res) => {
  const result = eval(req.body.code);
  res.json({ result });
});

// VULN: OS command injection — unsanitised input passed to shell
app.post('/ping', (req, res) => {
  exec('ping -c 1 ' + req.body.host, (err, stdout) => {
    res.send(stdout);
  });
});

// VULN: Hardcoded admin credential
const ADMIN_PASSWORD = 'admin123';

// VULN: JWT secret hardcoded in source
const JWT_SECRET = 'my-super-secret-jwt-key-do-not-share';

app.listen(3000);
