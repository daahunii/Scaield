import { ArrowLeft } from "lucide-react";
import { ContentHeader } from "../../components/layout/ContentHeader.jsx";
import { DashboardScreen } from "./screens/DashboardScreen.jsx";
import { ReportScreen } from "./screens/ReportScreen.jsx";
import { ScanningScreen } from "./screens/ScanningScreen.jsx";
import { SetupScreen } from "./screens/SetupScreen.jsx";

const scannerDescriptions = {
  setup: "스캔 환경 구성을 세팅하고 자동화 진단을 실행합니다.",
  scanning: "DVWA 모의 환경 모의침투 테스트 및 정밀 크롤링을 수행하고 있습니다.",
  dashboard: "모의 진단 분석 결과 대시보드 리포트가 요약되었습니다.",
  report: "AI LLM 분석 엔진이 탐지된 근거를 종합하여 작성한 심층 리포트입니다.",
};

export function ScannerView({ scanner }) {
  const {
    activeScreen,
    setActiveScreen,
    targetUrl,
    setTargetUrl,
    scanType,
    setScanType,
    rateLimit,
    setRateLimit,
    progress,
    currentStep,
    result,
    selectedVulnerability,
    setSelectedId,
    counts,
    error,
    isAiGenerating,
    aiReportReady,
    aiReportMessage,
    handleStartScan,
    resetToSetup,
  } = scanner;

  return (
    <div className="workspace-content">
      <ContentHeader
        title="Security Scanner"
        description={scannerDescriptions[activeScreen]}
        actions={
          <ScannerHeaderActions
            activeScreen={activeScreen}
            onBackToDashboard={() => setActiveScreen("dashboard")}
            onReset={resetToSetup}
          />
        }
      />

      {activeScreen === "setup" && (
        <SetupScreen
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          scanType={scanType}
          setScanType={setScanType}
          rateLimit={rateLimit}
          setRateLimit={setRateLimit}
          error={error}
          onSubmit={handleStartScan}
        />
      )}

      {activeScreen === "scanning" && (
        <ScanningScreen progress={progress} currentStep={currentStep} />
      )}

      {activeScreen === "dashboard" && (
        <DashboardScreen
          result={result}
          counts={counts}
          selectedVulnerability={selectedVulnerability}
          setSelectedId={setSelectedId}
          isAiGenerating={isAiGenerating}
          aiReportReady={aiReportReady}
          aiReportMessage={aiReportMessage}
          onOpenReport={() => setActiveScreen("report")}
          onReset={resetToSetup}
        />
      )}

      {activeScreen === "report" && (
        <ReportScreen targetUrl={targetUrl} selectedVulnerability={selectedVulnerability} />
      )}
    </div>
  );
}

function ScannerHeaderActions({ activeScreen, onBackToDashboard, onReset }) {
  if (activeScreen === "dashboard") {
    return (
      <button className="button-secondary-pill" onClick={onReset} type="button">
        <ArrowLeft size={16} />
        <span>메인 화면으로 돌아가기</span>
      </button>
    );
  }

  if (activeScreen === "report") {
    return (
      <div style={{ display: "flex", gap: "12px" }}>
        <button className="button-secondary-pill" onClick={onBackToDashboard} type="button">
          <ArrowLeft size={16} />
          <span>대시보드로 돌아가기</span>
        </button>
        <button className="button-secondary-pill" onClick={onReset} type="button">
          <ArrowLeft size={16} />
          <span>메인 화면으로 돌아가기</span>
        </button>
      </div>
    );
  }

  return null;
}
