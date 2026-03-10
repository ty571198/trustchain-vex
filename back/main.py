from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import json
import os
import shutil
import git  # pip install GitPython 필수
import google.generativeai as genai

app = FastAPI()

# CORS 설정: 프론트엔드와 통신 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Render 환경변수에서 API 키 로드
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

@app.get("/")
def root():
    return {"message": "TrustChain-VEX API is running"}

@app.get("/api/scan")
async def scan_github_repo(repo_url: str = Query(...)):
    # 1. 임시 작업 디렉토리 설정
    tmp_dir = "/tmp/repo_to_scan"
    
    try:
        # 기존에 폴더가 있다면 삭제 후 새로 생성
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        
        # 2. GitHub 저장소 Clone (최신 커밋 1개만 가져와서 속도 향상)
        print(f"Cloning repo: {repo_url}")
        git.Repo.clone_from(repo_url, tmp_dir, depth=1)

        # 3. Grype 스캔 실행 (JSON 결과)
        print("Running Grype scan...")
        process = subprocess.run(
            ["grype", tmp_dir, "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        scan_data = json.loads(process.stdout)
        
        # 4. 상위 5개 취약점 AI 분석 (시연 효율성)
        matches = scan_data.get("matches", [])[:5]
        total_count = len(scan_data.get("matches", []))
        
        model = genai.GenerativeModel('gemini-1.5-flash')
        analyzed_details = []

        for m in matches:
            v = m['vulnerability']
            pkg = m['artifact']['name']
            cve_id = v['id']
            desc = v.get('description', 'No description available')
            
            # AI 분석 프롬프트
            prompt = f"""
            Analyze the following vulnerability for a VEX report:
            - CVE ID: {cve_id}
            - Package: {pkg}
            - Description: {desc}
            
            Determine if this is likely 'AFFECTED' or 'NOT_AFFECTED' based on typical usage.
            Provide a 1-sentence justification in Korean.
            Format: [STATUS] | [REASON]
            """
            
            response = model.generate_content(prompt)
            ai_text = response.text.strip()
            
            status, reason = ai_text.split("|") if "|" in ai_text else ("UNKNOWN", ai_text)

            analyzed_details.append({
                "id": cve_id,
                "package": pkg,
                "severity": v.get('severity', 'Medium'),
                "status": status.strip(),
                "reason": reason.strip()
            })

        # 5. 스캔 완료 후 임시 폴더 삭제 (용량 관리)
        shutil.rmtree(tmp_dir)

        return {
            "summary": {
                "total": total_count,
                "analyzed": len(analyzed_details)
            },
            "details": analyzed_details
        }

    except Exception as e:
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))