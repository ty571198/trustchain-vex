# 🔴 VulnPath Analyzer

소스 코드의 취약 함수 **도달 가능성(Reachability)**을 정적 분석으로 시각화하는 Streamlit MVP 앱.

---

## 📁 파일 구조

```
vuln-analyzer/
├── app.py                  ← Streamlit 메인 앱
├── requirements.txt        ← 의존성 패키지
├── runtime.txt             ← Python 버전
├── .streamlit/
│   └── config.toml         ← Render 배포 설정
└── README.md
```

---

## 🚀 Render 배포 방법

### 1단계 — GitHub 저장소 준비
```bash
git init
git add .
git commit -m "init: VulnPath Analyzer MVP"
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

### 2단계 — Render Web Service 생성
1. [render.com](https://render.com) → **New + → Web Service**
2. GitHub 저장소 연결
3. 아래 설정 입력:

| 항목 | 값 |
|------|-----|
| **Name** | `vulnpath-analyzer` |
| **Region** | Singapore (or closest) |
| **Branch** | `main` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `streamlit run app.py --server.port 10000 --server.address 0.0.0.0` |
| **Instance Type** | Free |

4. **Create Web Service** 클릭 → 배포 완료!

> ⚠️ **포트 주의**: Render Free 플랜은 `10000` 포트를 사용합니다.  
> `.streamlit/config.toml`에 이미 설정되어 있으므로 Start Command와 일치시키면 됩니다.

---

## 💻 로컬 실행

```bash
# 의존성 설치
pip install -r requirements.txt

# 앱 실행
streamlit run app.py
```

---

## 🔬 기능 요약

| 기능 | 설명 |
|------|------|
| C/C++ 파싱 | 함수 정의 및 호출 관계 정규식 추출 |
| Call-Graph | NetworkX DiGraph 구축 |
| 경로 탐색 | `nx.all_simple_paths` — 모든 실행 경로 반환 |
| 시각화 | pyvis 대화형 그래프 (위험 경로 빨간색 강조) |
| VEX 리포트 | OpenVEX 형식 JSON 다운로드 |

---

## 📌 Start Command (복사용)

```
streamlit run app.py --server.port 10000 --server.address 0.0.0.0
```
