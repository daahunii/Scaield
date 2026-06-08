import { ContentHeader } from "../../components/layout/ContentHeader.jsx";

export function ProfileView() {
  return (
    <div className="workspace-content">
      <ContentHeader
        title="Developer Profile"
        description="스캐너 사용 주체의 인증 자격 상태 및 API 접근 크레덴셜을 열람합니다."
      />

      <div className="profile-layout animated-view">
        <div className="license-card">
          <div className="license-card-header">
            <div className="license-card-logo">
              <div className="license-card-logo-glyph">S</div>
              <span className="license-card-logo-text">Scaield Identity</span>
            </div>
            <div className="license-badge-glow">Active</div>
          </div>

          <div className="license-card-chip" />

          <div className="license-card-body">
            <div className="license-user-name">jonghyun</div>
            <div
              style={{
                fontSize: "14px",
                color: "var(--colors-magenta)",
                fontWeight: "500",
                letterSpacing: "-0.2px",
              }}
            >
              Enterprise Security Administrator
            </div>
          </div>

          <div className="license-card-footer">
            <div className="license-footer-item">
              <span className="license-footer-label">License ID</span>
              <span className="license-footer-value tnum">LIC-9482-JH26</span>
            </div>
            <div className="license-footer-item" style={{ alignItems: "flex-end" }}>
              <span className="license-footer-label">Valid Thru</span>
              <span className="license-footer-value tnum">2028. 12. 31</span>
            </div>
          </div>
        </div>

        <div className="profile-right-panels">
          <div className="sub-panel-view" style={{ padding: "32px" }}>
            <h3>Scaield Core API 연동 설정</h3>

            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div className="form-group">
                <label htmlFor="api-base-url-input">API Base Endpoint</label>
                <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                  <input
                    id="api-base-url-input"
                    className="text-input"
                    style={{ paddingLeft: "16px", fontFamily: "monospace", fontSize: "12px" }}
                    value="VITE_API_BASE_URL=http://localhost:8000"
                    readOnly
                  />
                  <button
                    className="button-secondary-pill"
                    style={{ position: "absolute", right: "6px", height: "32px", fontSize: "11px" }}
                    onClick={() => {
                      navigator.clipboard.writeText("VITE_API_BASE_URL=http://localhost:8000");
                      alert("API base URL 예시가 클립보드에 복사되었습니다.");
                    }}
                    type="button"
                  >
                    복사
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="api-token-input">Administrator API Token (Placeholder)</label>
                <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                  <input
                    id="api-token-input"
                    className="text-input"
                    style={{ paddingLeft: "16px", fontFamily: "monospace", fontSize: "12px" }}
                    value="sc_live_placeholder_••••••••••••"
                    readOnly
                  />
                  <button
                    className="button-secondary-pill"
                    style={{ position: "absolute", right: "6px", height: "32px", fontSize: "11px" }}
                    onClick={() => {
                      navigator.clipboard.writeText("sc_live_placeholder");
                      alert("placeholder token 예시가 클립보드에 복사되었습니다.");
                    }}
                    type="button"
                  >
                    복사
                  </button>
                </div>
              </div>

              <span style={{ fontSize: "11.5px", color: "var(--colors-ink-mute)", lineHeight: "1.4" }}>
                실제 API key나 비밀값은 프론트엔드 환경변수에 직접 넣지 말고, 반드시 백엔드 미들웨어에서 거쳐 관리하도록 설정하는 것을 권장합니다.
              </span>
            </div>
          </div>

          <div className="sub-panel-view" style={{ padding: "32px" }}>
            <h3>이번 달 플랜 사용 통계</h3>

            <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "8px" }}>
              <UsageStat label="모의 취약점 진단 횟수" value="45 / 무제한" />
              <UsageStat label="AI 리포트 생성 건수" value="128 / 무제한" />
              <UsageStat
                label="동시 최대 스캔 속도 (Rate Limit Limit)"
                value="30 req/s (최대 지원 속도)"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function UsageStat({ label, value }) {
  return (
    <div className="stat-item">
      <div className="stat-item-header">
        <span className="stat-label">{label}</span>
        <span className="stat-value tnum">{value}</span>
      </div>
      <div className="stat-progress-bar">
        <div className="stat-progress-fill" style={{ width: "100%" }} />
      </div>
    </div>
  );
}
