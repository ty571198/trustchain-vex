# 1. 파이썬 3.11 버전이 깔린 가상 컴퓨터를 기초로 삼음
FROM python:3.11-slim

# 2. 우리 서비스에 필요한 도구들(curl, git)과 핵심 스캐너(Grype)를 설치
# 이 과정이 있어야 서버가 "스캔" 기능을 가질 수 있습니다.
RUN apt-get update && apt-get install -y curl git && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get clean

# 3. 서버 내부의 작업 공간을 /app으로 정함
WORKDIR /app

# 4. 라이브러리 목록 파일을 복사하고 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 내 소스 코드(main.py 등)를 서버 안으로 전부 복사
COPY . .

# 6. 서버 실행 (Render가 정해주는 포트 번호($PORT)를 사용하도록 설정)
CMD uvicorn main:app --host 0.0.0.0 --port $PORT