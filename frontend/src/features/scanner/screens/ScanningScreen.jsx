export function ScanningScreen({ progress, currentStep }) {
  return (
    <div className="scanning-card animated-view">
      <div className="scanning-radar">
        <div className="radar-circle" />
        <div className="radar-circle" />
        <div className="radar-circle" />
        <div className="radar-core">
          <span className="tnum">{progress}%</span>
        </div>
      </div>

      <div className="scanning-progress-info">
        <h3>모의 취약점 분석 엔진 작동 중</h3>
        <p>안전한 환경에서 크롤링 및 인젝션 정밀 모니터링을 진행하고 있습니다.</p>
      </div>

      <div className="scanning-active-ticker">
        <div className="ticker-pulse" />
        <span>{currentStep}</span>
      </div>

      <div className="scanning-progress-track">
        <div className="scanning-progress-bar" style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
}
