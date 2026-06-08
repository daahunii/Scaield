import { Bot, RefreshCw } from "lucide-react";
import { ContentHeader } from "../../components/layout/ContentHeader.jsx";

export function ArchiveView({ archiveList, loadingArchive, onLoadArchiveScan }) {
  return (
    <div className="workspace-content">
      <ContentHeader
        title="리포트 보관함 (Scan Archive)"
        description="이전에 진단한 웹 취약점 진단 이력을 불러와 결과를 신속히 재현하고 분석합니다."
      />

      <div className="sub-panel-view animated-view">
        <h3>과거 취약점 모의 스캔 리스트</h3>

        {loadingArchive ? (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              padding: "80px 40px",
              gap: "16px",
            }}
          >
            <RefreshCw
              className="spin-loader"
              size={32}
              style={{ color: "var(--colors-primary)" }}
            />
            <span style={{ fontSize: "14px", color: "var(--colors-ink-mute)" }}>
              보관된 리포트를 불러오는 중...
            </span>
          </div>
        ) : archiveList.length > 0 ? (
          <div className="archive-grid">
            {archiveList.map((archiveItem) => (
              <button
                key={archiveItem.scan_id}
                className="archive-card"
                onClick={() => onLoadArchiveScan(archiveItem)}
                type="button"
              >
                <div className="archive-card-top">
                  <h4>{archiveItem.target_url}</h4>
                  <p>스캔 수행일자: {archiveItem.date}</p>
                </div>

                <div className="archive-card-bottom">
                  <span className="tnum" style={{ color: "var(--colors-ink-mute)" }}>
                    스캔 수행 시간: {archiveItem.scan_time}
                  </span>
                  <span className={`risk-badge ${archiveItem.risk_level.toLowerCase()}`}>
                    {archiveItem.risk_level} Risk
                  </span>
                </div>
              </button>
            ))}
          </div>
        ) : (
          <div className="empty-state-card" style={{ padding: "80px 40px" }}>
            <Bot size={40} />
            <h4>보관된 리포트가 없습니다.</h4>
            <p>스캔을 완료하면 결과 리포트가 디스크 파일로 자동 보관됩니다.</p>
          </div>
        )}
      </div>
    </div>
  );
}
