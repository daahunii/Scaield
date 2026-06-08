import {
  Activity,
  AlertTriangle,
  Code,
  Database,
  Download,
  ShieldAlert,
  Zap,
} from "lucide-react";

export function ReportScreen({ targetUrl, selectedVulnerability }) {
  if (!selectedVulnerability?.ai_report) {
    return null;
  }

  const report = selectedVulnerability.ai_report;

  return (
    <div className="report-view animated-view">
      <div className="report-header-panel">
        <div className="report-header-left">
          <h1>AI Deep Security Report</h1>
          <p>
            대상 호스트 URL: <strong className="tnum">{targetUrl}</strong> · 취약점 유형:{" "}
            {selectedVulnerability.type}
          </p>
        </div>

        <div className="report-action-buttons">
          <button className="button-secondary-pill" onClick={() => window.print()} type="button">
            <Download size={16} />
            <span>PDF 리포트 다운로드</span>
          </button>
        </div>
      </div>

      <div className="report-grid">
        <ReportSection icon={ShieldAlert} title="취약점 발견 요약" text={report.vulnerability_summary} />
        <ReportSection icon={Code} title="발생 원인 (Root Cause)" text={report.root_cause} />
        <ReportSection icon={Zap} title="위험성 및 공격 시나리오" text={report.attack_scenario} />
        <ReportSection icon={Database} title="안전한 코딩 수칙 가이드라인" text={report.secure_coding_guidance} />

        <section className="report-section code-highlight">
          <div className="report-section-title">
            <Code size={18} />
            <span>보안 결함 수정 소스코드 예시</span>
          </div>
          <p>{report.fixed_code_example}</p>
        </section>

        <ReportSection icon={Activity} title="보안 조치 재검증 절차" text={report.validation_steps} />

        <section className="report-section report-disclaimer">
          <div className="report-section-title">
            <AlertTriangle size={18} />
            <span>보안 권고 면책 조항</span>
          </div>
          <p>{report.disclaimer}</p>
        </section>
      </div>
    </div>
  );
}

function ReportSection({ icon: Icon, title, text }) {
  return (
    <section className="report-section">
      <div className="report-section-title">
        <Icon size={18} />
        <span>{title}</span>
      </div>
      <p>{text}</p>
    </section>
  );
}
