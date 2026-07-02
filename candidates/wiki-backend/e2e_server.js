// e2e: authMiddleware 격리 실행 (DB 불필요). 실제 verify.token 로직 재현.
// BRANCH=vuln → 하드코딩 시크릿 / BRANCH=fixed → env 시크릿
const express = require('express');
const jwt = require('jsonwebtoken');

const BRANCH = process.env.BRANCH || 'vuln';
// 취약: git에 박힌 시크릿 / 수정: env (공격자 모름)
const secretKey = BRANCH === 'fixed'
  ? (process.env.JWT_SECRET || 'prod-secret-not-in-git')
  : 'my-secret-key';

// verify.token.ts authMiddleware 그대로
const authMiddleware = (req, res, next) => {
  const token = req.header('x-auth-token')?.toString();
  if (!token) return res.status(401).json({ msg: '토큰 없음' });
  try {
    req.user = jwt.verify(token, secretKey);
    next();
  } catch (err) {
    return res.status(401).json({ msg: '토큰 무효' });
  }
};

const app = express();
// 보호 라우트 (article.controller 재현)
app.get('/article', authMiddleware, (req, res) => {
  res.status(200).json({ msg: '보호 데이터', user: req.user });
});

app.listen(10000, () => console.log(`[e2e] BRANCH=${BRANCH} :10000`));
