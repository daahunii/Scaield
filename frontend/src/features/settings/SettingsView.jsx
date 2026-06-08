import { ContentHeader } from "../../components/layout/ContentHeader.jsx";

export function SettingsView({
  targetDomain,
  scanDepth,
  setScanDepth,
  sessionCookie,
  setSessionCookie,
  customHeader,
  setCustomHeader,
  customHeaderParsed,
}) {
  return (
    <div className="workspace-content">
      <ContentHeader
        title="Scan Settings"
        description="스캐너의 분석 크롤링 레벨, HTTP 헤더 인증 매개변수 및 성능 규격을 조정합니다."
      />

      <div className="settings-layout animated-view">
        <div className="sub-panel-view settings-form-panel">
          <h3>스캐닝 작동 세부 파라미터</h3>

          <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <div className="form-group">
              <label htmlFor="scan-depth-select">최대 크롤링 분석 깊이 (Max Depth)</label>
              <select
                id="scan-depth-select"
                className="select-input"
                value={scanDepth}
                onChange={(event) => setScanDepth(Number(event.target.value))}
              >
                <option value={1}>1단계 (단일 홈페이지만 진단)</option>
                <option value={2}>2단계 (서브도메인 한정)</option>
                <option value={3}>3단계 (기본 하위 디렉토리)</option>
                <option value={5}>5단계 (정밀 분석 깊이)</option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="session-cookie-input">
                대상 모의환경 인증용 Session Cookie 값
              </label>
              <input
                id="session-cookie-input"
                className="text-input"
                style={{ paddingLeft: "16px" }}
                value={sessionCookie}
                onChange={(event) => setSessionCookie(event.target.value)}
                placeholder="PHPSESSID=..."
              />
              <span style={{ fontSize: "11px", color: "var(--colors-ink-mute)" }}>
                DVWA 보안 단계 설정(예: security=low) 등을 브라우저 세션 정보와 동기화하기 위한 용도입니다.
              </span>
            </div>

            <div className="form-group">
              <label htmlFor="custom-header-input">스캐너 차단 우회용 커스텀 HTTP 헤더</label>
              <input
                id="custom-header-input"
                className="text-input"
                style={{ paddingLeft: "16px" }}
                value={customHeader}
                onChange={(event) => setCustomHeader(event.target.value)}
                placeholder="User-Agent: ..."
              />
            </div>

            <div style={{ marginTop: "12px" }}>
              <button
                className="button-primary-pill"
                style={{ width: "auto", padding: "0 28px" }}
                onClick={() => alert("스캐너 세부 설정이 저장되었습니다.")}
                type="button"
              >
                <span>설정 저장</span>
              </button>
            </div>
          </div>
        </div>

        <div className="sub-panel-view preview-panel">
          <h3>스캐너 요청 헤더 시뮬레이션</h3>

          <div className="mockup-console">
            <div className="mockup-console-header">
              <span className="console-dot red" />
              <span className="console-dot yellow" />
              <span className="console-dot green" />
              <span className="console-title">Request HTTP Packet</span>
            </div>
            <div className="console-lines-container">
              <div className="console-line">
                <span className="console-keyword">GET</span>{" "}
                <span className="console-string">/dvwa/vulnerabilities/sqli/ HTTP/1.1</span>
              </div>
              <div className="console-line">
                <span className="console-keyword">Host:</span>{" "}
                <span className="console-string">{targetDomain}</span>
              </div>
              <div className="console-line">
                <span className="console-keyword">User-Agent:</span>{" "}
                <span className="console-string">
                  Scaield-Vulnerability-Engine/1.2 (LLM-Powered)
                </span>
              </div>
              {sessionCookie && (
                <div className="console-line">
                  <span className="console-keyword">Cookie:</span>{" "}
                  <span className="console-string">{sessionCookie}</span>
                </div>
              )}
              {customHeaderParsed && (
                <div className="console-line">
                  <span className="console-keyword">{customHeaderParsed.name}:</span>{" "}
                  <span className="console-string">{customHeaderParsed.value}</span>
                </div>
              )}
              <div className="console-line">
                <span className="console-comment">// Max Crawl Depth: {scanDepth} stages</span>
              </div>
              <div className="console-line">
                <span className="console-keyword">Accept:</span>{" "}
                <span className="console-string">
                  text/html,application/xhtml+xml,application/xml;q=0.9
                </span>
              </div>
              <div className="console-line">
                <span className="console-keyword">Connection:</span>{" "}
                <span className="console-string">keep-alive</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
