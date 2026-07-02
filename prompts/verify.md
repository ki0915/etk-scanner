# $verify — PoC 검증 및 DA 리뷰

## PoC 생성 원칙

- 입력(Payload)과 트리거를 명확히 분리하여 구현
- 최소한의 코드로 취약점을 재현
- 실행 환경과 의존성을 명시

## PoC 파일 구조

```
vuln-001/
├── poc.py (또는 poc.js)   # 실제 PoC 코드
├── requirements.txt        # 의존성 (있을 경우)
└── README.md              # 실행 방법 및 예상 결과
```

## PoC README 형식

```markdown
## 환경
- Python X.X / Node X.X
- 패키지 버전: X.X.X

## 실행 방법
pip install <package>==X.X.X
python poc.py

## 예상 결과
[정상 실행 시 나타나야 하는 출력 또는 증거]

## 취약점 설명
[한 문단으로 무엇이 왜 취약한지]
```

## DA (Devil's Advocate) 리뷰 체크리스트

maintainer 입장에서 이 제보를 거부해야 한다면 어떤 근거를 댈 수 있는가?

- [ ] 이 코드에 사용자 입력이 실제로 도달하는가?
- [ ] 기존 문서에서 이 동작이 의도된 것으로 설명되어 있는가?
- [ ] 공격자가 이 취약점을 악용하려면 어떤 전제조건이 필요한가?
- [ ] 유사한 Issue/PR이 이미 존재하고 maintainer가 거부한 적 있는가?
- [ ] 이 취약점이 실제 피해로 이어지는 시나리오가 현실적인가?

DA 리뷰 후에도 유효하면 → 리포트 생성으로 이동
DA 리뷰에서 반박 근거가 충분하면 → STOP 처리
