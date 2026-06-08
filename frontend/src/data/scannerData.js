export const scanSteps = [
  "Target URL 확인 중...",
  "서브도메인 및 하위 링크 크롤링 중...",
  "입력 Form 및 취약점 진입점 탐색 중...",
  "SQL Injection Payload 테스트 진행 중...",
  "Reflected XSS 취약점 인젝션 진행 중...",
  "서버 응답 상태 코드 및 DOM 형태 분석 중...",
  "취약점 탐지 결과 파싱 및 DB 구조 검토 중...",
  "LLM 보안 분석 엔진 리포트 초안 작성 중...",
];

export const severityRank = {
  High: 3,
  Medium: 2,
  Low: 1,
};

export const mockArchive = [
  {
    scan_id: "archive-01",
    target_url: "http://localhost:8080/dvwa",
    date: "2026-06-01",
    risk_level: "High",
    vulnerabilities_count: 2,
    scan_time: "2분 14초",
  },
  {
    scan_id: "archive-02",
    target_url: "https://demo.testfire.net",
    date: "2026-05-24",
    risk_level: "High",
    vulnerabilities_count: 3,
    scan_time: "3분 05초",
  },
  {
    scan_id: "archive-03",
    target_url: "https://example.com/api",
    date: "2026-05-18",
    risk_level: "Low",
    vulnerabilities_count: 0,
    scan_time: "1분 40초",
  },
];

export function createMockArchiveResult(archiveItem) {
  return {
    scan_id: archiveItem.scan_id,
    target_url: archiveItem.target_url,
    scan_time: archiveItem.scan_time,
    total_pages: archiveItem.risk_level === "High" ? 12 : 5,
    tested_inputs: archiveItem.risk_level === "High" ? 18 : 6,
    risk_level: archiveItem.risk_level,
    report_status: "AI 리포트 초안 생성",
    vulnerabilities:
      archiveItem.risk_level === "High"
        ? [
            {
              id: "vuln-sqli-01",
              type: "SQL Injection",
              risk_level: "High",
              endpoint: "/dvwa/vulnerabilities/sqli/",
              parameter: "id",
              payload: "' OR 1=1--",
              status_code: 200,
              evidence: "참 조건과 거짓 조건 요청의 응답 길이 차이 발생",
              detection_method: "boolean_based",
              ai_report: {
                vulnerability_summary:
                  "id 파라미터에서 SQL Injection 가능성이 탐지되었습니다.",
                root_cause:
                  "사용자 입력이 SQL 쿼리에 안전하게 바인딩되지 않고 동적으로 결합되어 실행되고 있습니다.",
                attack_scenario:
                  "공격자는 조건식을 조작해 인증을 우회하고 데이터베이스 구조를 덤프할 수 있습니다.",
                secure_coding_guidance:
                  "Prepared Statement 또는 Parameterized Query를 사용하여 사용자 입력을 바인딩 처리하십시오.",
                fixed_code_example:
                  "SELECT * FROM users WHERE id = ? 형태의 파라미터 바인딩을 적용합니다.",
                validation_steps:
                  "동일 payload로 재검사했을 때 데이터 누출이나 응답 차이가 유실되는지 재실험합니다.",
                disclaimer:
                  "이 리포트는 자동 스캔 데이터를 바탕으로 자동 조립되었습니다. 실제 보완 작업 시 검토가 수반되어야 합니다.",
              },
            },
            {
              id: "vuln-xss-01",
              type: "Reflected XSS",
              risk_level: "Medium",
              endpoint: "/dvwa/vulnerabilities/xss_r/",
              parameter: "name",
              payload: "<script>alert('XSS_TEST')</script>",
              status_code: 200,
              evidence: "응답 HTML에 payload가 인코딩 필터 없이 그대로 반사됨",
              detection_method: "reflection",
              ai_report: {
                vulnerability_summary:
                  "name 파라미터에서 Reflected XSS 가능성이 탐지되었습니다.",
                root_cause:
                  "입력된 매개변수가 HTML 템플릿에 출력되기 전 적절하게 이스케이프되지 않았습니다.",
                attack_scenario:
                  "공격자가 조작된 피싱 URL을 사용자에게 유포하여 악성 스크립트를 세션 컨텍스트 내에서 실행시킬 수 있습니다.",
                secure_coding_guidance:
                  "출력 컨텍스트에 맞춰 특수 문자를 HTML Entity 형태로 치환(Escaping)하십시오.",
                fixed_code_example:
                  "htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 형식의 필터를 거쳐 출력합니다.",
                validation_steps:
                  "브라우저 콘솔에서 스크립트 실행이 차단되고 렌더링 결과에 특수 문자가 치환되어 출력되는지 검증합니다.",
                disclaimer:
                  "클라이언트 사이드 환경과 Content Security Policy 규격에 따라 침투 가능 범위가 변경될 수 있습니다.",
              },
            },
          ]
        : [],
  };
}
