import {
  AlertTriangle,
  Bot,
  Gauge,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

export function DashboardScreen({
  result,
  counts,
  selectedVulnerability,
  setSelectedId,
  isAiGenerating,
  aiReportReady,
  aiReportMessage,
  onOpenReport,
  onReset,
}) {
  return (
    <div className="dashboard-grid animated-view">
      <div className="ai-report-activation-banner">
        <div className="ai-activation-info">
          <div className={`ai-sparkle-box ${isAiGenerating ? "generating" : ""}`}>
            <Sparkles size={20} />
          </div>
          <div className="ai-activation-text">
            <h4>
              {isAiGenerating
                ? "AI LLM 보안 종합 취약점 리포트 초안 분석 중..."
                : aiReportReady
                  ? "AI LLM 종합 보안 리포트 생성 완료"
                  : "AI 리포트 생성 대기 중"}
            </h4>
            <p>
              {isAiGenerating
                ? "수집된 침투 로그와 코드 증거를 조합하여 취약점 패치 가이드를 기안 중입니다."
                : aiReportReady
                  ? "코드 보안 수정 예시 및 취약점 대응 권고사항이 요약 준비되었습니다."
                  : aiReportMessage ||
                    "백엔드 AI 리포트 설정 후 다시 스캔하면 AI 리포트가 생성됩니다."}
            </p>
          </div>
        </div>

        <button
          className="button-ai-cta"
          disabled={!aiReportReady}
          onClick={onOpenReport}
          type="button"
        >
          <Sparkles size={16} />
          <span>AI Report 보러가기</span>
        </button>
      </div>

      <div className="dashboard-stats">
        <article className="dashboard-metric-card">
          <div className="metric-header">
            <span>탐지된 취약점 후보</span>
            <div className="metric-icon-box warning">
              <ShieldAlert size={18} />
            </div>
          </div>
          <strong className="metric-value tnum">{counts.total || 0}</strong>
          <span className="metric-detail">
            SQLi: {counts.sqli}건 · XSS: {counts.xss}건
          </span>
        </article>

        <article className="dashboard-metric-card">
          <div className="metric-header">
            <span>서버 종합 보안 위험도</span>
            <div className="metric-icon-box primary">
              <Gauge size={18} />
            </div>
          </div>
          <strong
            className="metric-value"
            style={{
              color:
                result?.risk_level === "High"
                  ? "var(--colors-ruby)"
                  : "var(--colors-ink)",
            }}
          >
            {result?.risk_level || "Unknown"}
          </strong>
          <span className="metric-detail">{result?.report_status || "초안 생성 완료"}</span>
        </article>

        <article className="dashboard-metric-card">
          <div className="metric-header">
            <span>검증된 사용자 입력 개수</span>
            <div className="metric-icon-box success">
              <Search size={18} />
            </div>
          </div>
          <strong className="metric-value tnum">{result?.tested_inputs || 0}</strong>
          <span className="metric-detail">
            {result?.total_pages || 0}개의 모의 사이트 페이지 수집
          </span>
        </article>
      </div>

      <div className="dashboard-composite">
        <section className="vuln-list-panel">
          <div className="vuln-list-header">취약점 탐지 내역 목록</div>

          {result?.vulnerabilities?.length > 0 ? (
            result.vulnerabilities.map((item) => (
              <button
                key={item.id}
                className={`vuln-item-btn ${
                  selectedVulnerability?.id === item.id ? "selected" : ""
                }`}
                onClick={() => setSelectedId(item.id)}
                type="button"
              >
                <div className="vuln-item-info">
                  <span className="vuln-item-title">{item.type}</span>
                  <span className="vuln-item-path">{item.endpoint}</span>
                </div>
                <span className={`risk-badge ${item.risk_level.toLowerCase()}`}>
                  {item.risk_level}
                </span>
              </button>
            ))
          ) : (
            <div className="empty-state-card">
              <Bot size={28} />
              <h4>탐지된 취약점이 없습니다.</h4>
              <p>입력한 사이트가 모의 보안 취약 기준을 무사 통과했습니다.</p>
            </div>
          )}
        </section>

        <section className="detail-panel">
          {selectedVulnerability ? (
            <>
              <div className="detail-panel-header">
                <div className="detail-panel-title">
                  <h3>{selectedVulnerability.type}</h3>
                  <p>발견 고유 번호: {selectedVulnerability.id}</p>
                </div>
                <span className={`risk-badge ${selectedVulnerability.risk_level.toLowerCase()}`}>
                  {selectedVulnerability.risk_level}
                </span>
              </div>

              <div className="detail-table">
                <DetailRow label="발견 위치 (Endpoint)" value={selectedVulnerability.endpoint} />
                <DetailRow label="취약 매개변수 (Param)" value={selectedVulnerability.parameter} />
                <DetailRow
                  label="인젝션 Payload"
                  value={selectedVulnerability.payload}
                  valueClassName="payload-code"
                />
                <DetailRow label="탐지 방식" value={selectedVulnerability.detection_method} />
                <DetailRow label="탐지 근거" value={selectedVulnerability.evidence} />
              </div>

              <div className="detail-panel-actions">
                <button
                  className="button-secondary-pill button-secondary-dark"
                  onClick={onReset}
                  type="button"
                >
                  <RefreshCw size={14} />
                  <span>재스캔 수행</span>
                </button>
              </div>
            </>
          ) : (
            <div
              className="empty-state-card"
              style={{ height: "100%", justifyContent: "center" }}
            >
              <AlertTriangle size={32} />
              <h4>데이터 부재</h4>
              <p>선택된 취약점의 세부 명세가 없습니다.</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function DetailRow({ label, value, valueClassName = "" }) {
  return (
    <div className="detail-table-row">
      <span className="detail-table-label">{label}</span>
      <span className={`detail-table-value ${valueClassName}`}>{value}</span>
    </div>
  );
}
