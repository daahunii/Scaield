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
                        os.environ[key.strip()] = value.strip()

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
너의 목표는 DAST 스캐너가 수집한 '원시 취약점 증거(Raw Evidence) JSON' 데이터를 분석하여, 보안 지식이 부족한 개발자도 즉시 이해하고 조치할 수 있는 '구조화된 보안 코칭 리포트'를 생성하는 것이다.

[Strict Rules & Constraints]

1. 할루시네이션(Hallucination) 엄격 금지 (가장 중요):

   * 오직 제공된 '스캔 증거 데이터(Payload, HTTP Status, Response Body 등)'에 기반해서만 분석해라.
   * 타겟 서버의 실제 소스코드가 너에게 제공되지 않았으므로, 존재하지 않는 파일명, 클래스명, 라인 번호 등을 절대 임의로 지어내거나 추측하지 마라.

2. OWASP 기반 시큐어 코딩 가이드:

   * 취약점 조치 방안은 반드시 OWASP Secure Coding Guidelines를 준수해야 한다.
   * 프레임워크 문맥(예: Spring Boot, Node.js 등)이 로그를 통해 파악된다면 해당 프레임워크에 맞는 실제 적용 가능한 방어 코드 스니펫(예: Prepared Statement 등)을 제공해라.

3. 면책 조항(Disclaimer) 필수 포함:

   * 네가 제안하는 코드는 실제 코드를 보고 짠 것이 아니므로, 리포트의 마지막에는 반드시 다음 면책 조항을 정확히 포함해라: '본 리포트와 제안된 코드는 스캐너의 외부 관측 증거를 바탕으로 작성된 참고용 예시입니다. 실제 프로덕션 서비스에 적용하기 전 반드시 개발자 및 보안 담당자의 검토가 필요합니다.'

[Input Data Format (Context)]

* 사용자의 프롬프트(User Message)로는 스캐너로부터 전달된 JSON 형식의 증거 데이터 (Endpoint, Parameter, Injected Payload, HTTP Status, Response Body, Evidence Type 등)가 제공될 것이다.

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
