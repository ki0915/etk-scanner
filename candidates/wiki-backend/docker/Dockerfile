# wiki-backend 실행용 (e2e 보안 검증 목적)
FROM node:20-slim

WORKDIR /app

# 소스 복사 (repo/Back-end 기준 빌드 컨텍스트)
COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 10000

# ts 직접 실행 (nodemon 대신 ts-node, dev 의존성)
RUN npm install -g ts-node typescript

CMD ["ts-node", "src/app.ts"]
