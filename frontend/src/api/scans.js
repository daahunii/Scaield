const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"
).replace(/\/$/, "");

export const isMockApi = import.meta.env.VITE_USE_MOCK_API === "true";

export async function startScan(payload) {
  if (isMockApi) {
    return createMockScan(payload);
  }

  const response = await fetch(`${API_BASE_URL}/scan/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error("스캔 시작 요청에 실패했습니다.");
  }

  return response.json();
}

export async function getScanStatus(scanId) {
  if (isMockApi) {
    return createMockStatus(scanId);
  }

  const response = await fetch(`${API_BASE_URL}/scan/${scanId}/status`);

  if (!response.ok) {
    throw new Error("스캔 상태 조회에 실패했습니다.");
  }

  return response.json();
}

export async function getScanResult(scanId) {
  if (isMockApi) {
    return createMockResult(scanId);
  }

  const response = await fetch(`${API_BASE_URL}/scan/${scanId}/result`);

  if (!response.ok) {
    throw new Error("스캔 결과 조회에 실패했습니다.");
  }

  return response.json();
}

export async function getScanList() {
  if (isMockApi) {
    return Promise.resolve([
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
    ]);
  }

  const response = await fetch(`${API_BASE_URL}/scan/list`);

  if (!response.ok) {
    throw new Error("스캔 목록 조회에 실패했습니다.");
  }

  return response.json();
}

function createMockScan(payload) {
  return Promise.resolve({
    scan_id: `mock-${Date.now()}`,
    target_url: payload.target_url,
    status: "running",
  });
}

function createMockStatus(scanId) {
  return Promise.resolve({
    scan_id: scanId,
    status: "completed",
    progress: 100,
    current_step: "LLM 리포트 생성 완료",
  });
}

function createMockResult(scanId) {
  return Promise.resolve({
    scan_id: scanId,
    target_url: "http://localhost:8080/dvwa",
    scan_time: "2분 14초",
    total_pages: 12,
    tested_inputs: 18,
    risk_level: "High",
    report_status: "AI 리포트 초안 생성",
    vulnerabilities: [
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
            "제공된 응답 차이를 기준으로 볼 때 사용자 입력이 SQL 쿼리에 안전하게 바인딩되지 않았을 가능성이 있습니다.",
          attack_scenario:
            "공격자는 조건식을 조작해 인증 우회, 데이터 조회 범위 확장, 민감 정보 노출을 시도할 수 있습니다.",
          secure_coding_guidance:
            "문자열 결합으로 SQL문을 만들지 말고 Prepared Statement 또는 Parameterized Query를 사용하세요.",
          fixed_code_example:
            "SELECT * FROM users WHERE id = ? 형태의 파라미터 바인딩을 적용합니다.",
          validation_steps:
            "동일 payload로 재검사했을 때 참/거짓 조건의 응답이 의미 있게 달라지지 않는지 확인합니다.",
          disclaimer:
            "이 리포트는 관측된 스캔 근거에 기반한 자동 생성 결과이며 실제 반영 전 개발자 검토가 필요합니다.",
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
        evidence: "응답 HTML에 payload가 escape 없이 반사됨",
        detection_method: "reflection",
        ai_report: {
          vulnerability_summary:
            "name 파라미터에서 Reflected XSS 가능성이 탐지되었습니다.",
          root_cause:
            "사용자 입력이 HTML 응답에 출력되기 전에 적절히 이스케이프되지 않았을 가능성이 있습니다.",
          attack_scenario:
            "공격자는 조작된 링크를 통해 사용자의 브라우저에서 임의 스크립트 실행을 유도할 수 있습니다.",
          secure_coding_guidance:
            "출력 컨텍스트에 맞는 HTML escaping을 적용하고 CSP를 보조 방어 계층으로 구성하세요.",
          fixed_code_example:
            "서버 템플릿 출력 시 escape 함수를 사용하고 raw HTML 출력을 금지합니다.",
          validation_steps:
            "payload가 &lt;script&gt; 형태로 인코딩되어 렌더링되고 alert가 실행되지 않는지 확인합니다.",
          disclaimer:
            "문자열 반사 검사는 실행 검증이 아니므로 Selenium 검증 결과와 함께 판단하는 것이 좋습니다.",
        },
      },
    ],
  });
}
