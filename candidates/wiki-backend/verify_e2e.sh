#!/usr/bin/env bash
# e2e 보안 검증: 위조 JWT로 보호 라우트(/article) 접근 시도
# 취약 브랜치: 200 (위조 통과) / 수정 브랜치: 401 (거부)
set -u

BASE="http://localhost:10000"
LEAKED_SECRET="my-secret-key"     # git 공개 repo에 박혔던 시크릿

echo "=== e2e JWT 위조 검증 ==="
echo "대상: $BASE/article (authMiddleware 보호)"
echo

# 1. 앱 살아있나
for i in $(seq 1 30); do
  if curl -s -o /dev/null "$BASE/login" 2>/dev/null; then break; fi
  echo "  앱 대기중... ($i)"; sleep 2
done

# 2. 유출된 시크릿으로 admin 토큰 위조 (node + 앱의 실제 jsonwebtoken)
FORGED=$(node -e "
const jwt=require('./repo/Back-end/node_modules/jsonwebtoken');
console.log(jwt.sign({userId:'attacker-admin'}, '$LEAKED_SECRET', {expiresIn:'30m'}));
")
echo "위조 토큰(유출 시크릿 서명): ${FORGED:0:40}..."
echo

# 3. 위조 토큰으로 보호 라우트 접근
CODE=$(curl -s -o /tmp/e2e_body -w "%{http_code}" \
  -H "x-auth-token: $FORGED" "$BASE/article")

echo "HTTP 응답 코드: $CODE"
echo "본문: $(head -c 200 /tmp/e2e_body)"
echo

# 4. 판정
if [ "$CODE" = "401" ]; then
  echo ">> FIXED: 위조 토큰 거부됨 (서버가 env 시크릿 사용, 유출 시크릿 무효)"
  exit 0
elif [ "$CODE" = "200" ]; then
  echo ">> VULNERABLE: 위조 토큰으로 보호 라우트 접근 성공 (자격증명 0)"
  exit 1
else
  echo ">> 판정 불가 (코드 $CODE) — 앱/DB 상태 확인"
  exit 2
fi
