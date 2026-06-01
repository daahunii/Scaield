import json
import os
import google.generativeai as genai

def load_env():
    """
    Load environment variables from a .env file in the project root.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(base_dir, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip().strip("'\"")

# Load environment variables on import
load_env()

def load_results(file_path="pipeline/results.json"):
    """
    Load the vulnerability scanning results from the specified JSON file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: The file {file_path} contains invalid JSON.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while loading {file_path}: {e}")
        return None

def generate_report(results_data, api_key=None, model_name="gemini-3.5-flash"):
    """
    Generate a vulnerability report using the Gemini API based on the provided results data.
    """
    if not results_data:
        return "No results data provided. Cannot generate report."

    # Use the provided API key, or look for it in the environment variables
    if api_key is None:
        api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return "Error: Gemini API key not provided and GEMINI_API_KEY not found in environment."

    genai.configure(api_key=api_key)
    
    # Initialize the model
    model = genai.GenerativeModel(model_name)

    prompt = f"""
    [System Role]
    너는 'Scaield' 시스템의 수석 웹 애플리케이션 보안 전문가(Senior AppSec Engineer)이자 개발자를 위한 보안 코치야.
    너의 목표는 DAST 스캐너가 수집한 '원시 취약점 증거(Raw Evidence) JSON' 데이터를 DAST 결과 요약 형식으로 분석하여, 프론트엔드가 대시보드와 PDF 리포트 화면에 각각 나누어 렌더링할 수 있도록 완벽하게 구조화된 JSON 데이터를 생성하는 것이다.

    [Strict Rules & Constraints]
    1. 할루시네이션(Hallucination) 엄격 금지 (NFR3):
    - 오직 제공된 '스캔 증거 데이터(Payload, HTTP Status, Response Body, Error Log 등)'에 기반해서만 분석해라.
    - 타겟 서버의 실제 소스코드가 너에게 제공되지 않았으므로, 존재하지 않는 파일명, 클래스명, 라인 번호 등을 절대 임의로 지어내거나 단정 짓지 마라.
    2. OWASP 기반 시큐어 코딩 가이드 (NFR4):
    - 취약점 조치 방안은 반드시 OWASP Secure Coding Guidelines를 준수해야 한다.
    - 로그를 통해 사용 중인 프레임워크(예: Spring Boot, Python 등)가 파악된다면, 해당 환경에 맞는 방어 코드 스니펫(예: Prepared Statement 등)을 제공해라.
    3. 출력 형식 강제 (JSON Only):
    - 네 응답은 반드시 아래에 제공된 JSON 스키마 구조를 100% 준수해야 한다.
    - JSON 블록 외에 인사말, 마크다운 코드 블록(```json) 기호, 부연 설명 텍스트는 절대 출력하지 마라.
    - 생각 과정(Thinking Process)을 절대 응답에 포함하지 마십시오. 생각 과정 없이 곧바로 JSON 결과값만 출력하세요.
    - CRITICAL: DO NOT use <thought> or generate any thinking/reasoning process. Immediately output the JSON response. Do not output anything else.

    [Output Data Format (JSON Schema)]
    네가 생성해야 할 JSON은 대시보드 렌더링용 데이터("dashboard_view")와 PDF 상세 리포트용 데이터("pdf_report_view")로 나뉜다. 아래 형식을 정확히 지켜서 출력해라.

    {{
    "dashboard_view": {{
    "vulnerability_title": "탐지된 취약점의 공식 명칭 (예: SQL Injection (Error-based))",
    "risk_level": "High, Medium, Low 중 택 1",
    "affected_parameter": "취약점이 발견된 파라미터명 또는 엔드포인트",
    "brief_summary": "대시보드 메인에 띄울 취약점의 핵심을 1~2줄로 요약한 문장"
    }},
    "pdf_report_view": {{
    "technical_root_cause": "해당 취약점이 왜 발생했는지 논리적이고 기술적인 근본 원인 상세 설명 (증거 내에서만 추론)",
    "business_impact_scenario": "공격자가 이를 악용할 경우 발생할 수 있는 비즈니스 영향도 및 구체적인 공격 시나리오",
    "secure_code_example": "취약점을 방어할 수 있는 올바른 수정 코드 스니펫 (마크다운 포맷으로 작성, 주석 포함)",
    "remediation_guidance": "코드를 수정하기 위한 구체적인 단계별 조치 가이드",
    "validation_checklist": [
        "코드 수정 후 취약점이 패치되었는지 다시 확인하는 방법 1",
        "코드 수정 후 취약점이 패치되었는지 다시 확인하는 방법 2"
    ],
    "disclaimer": "본 리포트와 제안된 코드는 스캐너의 외부 관측 증거를 바탕으로 작성된 참고용 예시입니다. 실제 프로덕션 서비스에 적용하기 전 반드시 개발자 및 보안 담당자의 검토가 필요합니다."
    }}
    }}

    {json.dumps(results_data, indent=2, ensure_ascii=False)}
    """


    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"An error occurred during report generation: {e}"

if __name__ == "__main__":
    # Example usage
    # Ensure you have your GEMINI_API_KEY set in your environment
    
    print("Loading results.json...")
    # Adjust path if running from a different directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_path = os.path.join(base_dir, "pipeline", "results.json")
    
    data = load_results(results_path)
    
    if data:
        print("Results loaded successfully. Generating report...")
        report = generate_report(data)
        
        print("\n--- Vulnerability Report ---\n")
        print(report)
        
        # Optionally, save to file
        report_path = os.path.join(base_dir, "pipeline", "report.md")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\nReport saved to {report_path}")
        except Exception as e:
            print(f"Failed to save report: {e}")
