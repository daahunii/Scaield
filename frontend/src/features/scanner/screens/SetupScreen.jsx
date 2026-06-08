import { Globe2, Play } from "lucide-react";

export function SetupScreen({
  targetUrl,
  setTargetUrl,
  scanType,
  setScanType,
  rateLimit,
  setRateLimit,
  error,
  onSubmit,
}) {
  return (
    <div className="setup-grid animated-view">
      <section className="brand-intro">
        <span className="eyebrow">LLM-Powered Vulnerability Scanner</span>
        <h1>취약점 탐지부터 리포트까지 한 화면에서.</h1>
        <p className="lead">
          DVWA 기반 크롤링과 SQLi/XSS 펜테스트 결과를 개발자가 바로 읽을 수 있는 보안 리포트 형태로 요약 정리합니다.
        </p>

        <div className="setup-visual">
          <div className="mockup-console">
            <div className="mockup-console-header">
              <span className="console-dot red" />
              <span className="console-dot yellow" />
              <span className="console-dot green" />
              <span className="console-title">Scaield Vulnerability Engine v1.2</span>
            </div>
            <div className="console-line">
              <span className="console-comment">// Target Server Environment Scan</span>
            </div>
            <div className="console-line">
              <span className="console-keyword">const</span> scanner ={" "}
              <span className="console-keyword">new</span> ScaieldScanner();
            </div>
            <div className="console-line">
              scanner.setTarget(<span className="console-string">"{targetUrl}"</span>);
            </div>
            <div className="console-line">
              scanner.addPayloads([<span className="console-string">"SQLi"</span>,{" "}
              <span className="console-string">"XSS"</span>]);
            </div>
            <div className="console-line">
              <span className="console-comment">
                // Rate limits set to {rateLimit} reqs/sec
              </span>
            </div>
            <div className="console-line">scanner.start();</div>
          </div>
        </div>
      </section>

      <form className="setup-card" onSubmit={onSubmit}>
        <div className="form-group">
          <label htmlFor="target-url-input">Target URL</label>
          <div className="input-container">
            <Globe2 size={16} />
            <input
              id="target-url-input"
              className="text-input"
              value={targetUrl}
              onChange={(event) => setTargetUrl(event.target.value)}
              placeholder="http://localhost:8080/dvwa"
              required
            />
          </div>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label htmlFor="scan-type-select">취약점 탐지 유형</label>
            <select
              id="scan-type-select"
              className="select-input"
              value={scanType}
              onChange={(event) => setScanType(event.target.value)}
            >
              <option value="all">전체 자동 스캔 (All)</option>
              <option value="sqli">SQL Injection 전용</option>
              <option value="xss">XSS 전용</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="rate-limit-input">Rate Limit (req/s)</label>
            <input
              id="rate-limit-input"
              className="select-input"
              type="number"
              min="1"
              max="30"
              value={rateLimit}
              onChange={(event) => setRateLimit(event.target.value)}
            />
          </div>
        </div>

        {error && (
          <p
            className="form-error"
            style={{ color: "var(--colors-error)", fontSize: "13px" }}
          >
            {error}
          </p>
        )}

        <div className="setup-card-footer">
          <button className="button-primary-pill" type="submit">
            <Play size={16} />
            <span>모의 진단 및 취약점 스캔 시작</span>
          </button>
        </div>
      </form>
    </div>
  );
}
