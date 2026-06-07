import React, { useMemo, useState, useEffect } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Bot,
  ChevronRight,
  Code,
  Database,
  Download,
  ExternalLink,
  FileText,
  Folder,
  Gauge,
  Globe2,
  Menu,
  Play,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  Sparkles,
  User,
  Zap,
} from "lucide-react";
import { getScanResult, getScanStatus, isMockApi, startScan, getScanList } from "./api/scans.js";

const scanSteps = [
  "Target URL 확인 중...",
  "서브도메인 및 하위 링크 크롤링 중...",
  "입력 Form 및 취약점 진입점 탐색 중...",
  "SQL Injection Payload 테스트 진행 중...",
  "Reflected XSS 취약점 인젝션 진행 중...",
  "서버 응답 상태 코드 및 DOM 형태 분석 중...",
  "취약점 탐지 결과 파싱 및 DB 구조 검토 중...",
  "LLM 보안 분석 엔진 리포트 초안 작성 중...",
];

const severityRank = {
  High: 3,
  Medium: 2,
  Low: 1,
};

// Mock archive items to show in the Report Archive
const mockArchive = [
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

function App() {
  // Sidebar tab state: "scanner" | "archive" | "settings" | "profile"
  const [activeTab, setActiveTab] = useState("scanner");

  // Scanner sub-screen state: "setup" | "scanning" | "dashboard" | "report"
  const [activeScreen, setActiveScreen] = useState("setup");

  // Core Form States
  const [targetUrl, setTargetUrl] = useState("http://localhost:8080/dvwa");
  const [scanType, setScanType] = useState("all");
  const [rateLimit, setRateLimit] = useState(10);

  // Scan Running States
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState("대기 중");
  const [result, setResult] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [error, setError] = useState("");

  // AI Report Async States
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [aiReportReady, setAiReportReady] = useState(false);
  const [aiReportMessage, setAiReportMessage] = useState("");

  // Archive States
  const [archiveList, setArchiveList] = useState([]);
  const [loadingArchive, setLoadingArchive] = useState(false);

  // Settings Configuration States (Inside settings tab)
  const [scanDepth, setScanDepth] = useState(3);
  const [sessionCookie, setSessionCookie] = useState("security=impossible; PHPSESSID=mock");
  const [customHeader, setCustomHeader] = useState("X-Scanner: Scaield-LLM");

  const targetDomain = useMemo(() => {
    try {
      const parsed = new URL(targetUrl);
      return parsed.host || "localhost:8080";
    } catch (e) {
      return "localhost:8080";
    }
  }, [targetUrl]);

  const customHeaderParsed = useMemo(() => {
    if (!customHeader) return null;
    const splitIndex = customHeader.indexOf(":");
    if (splitIndex === -1) {
      return { name: "Custom-Header", value: customHeader };
    }
    return {
      name: customHeader.substring(0, splitIndex).trim(),
      value: customHeader.substring(splitIndex + 1).trim(),
    };
  }, [customHeader]);

  // Filtered vulnerability selection
  const selectedVulnerability = useMemo(() => {
    if (!result?.vulnerabilities?.length) {
      return null;
    }
    return (
      result.vulnerabilities.find((item) => item.id === selectedId) ||
      result.vulnerabilities[0]
    );
  }, [result, selectedId]);

  // Statistics summaries
  const counts = useMemo(() => {
    const vulnerabilities = result?.vulnerabilities || [];
    return vulnerabilities.reduce(
      (summary, item) => {
        const type = String(item.type || "").toLowerCase();
        summary.total += 1;
        if (type.includes("sql injection") || type.includes("sqli")) {
          summary.sqli += 1;
        }
        if (type.includes("xss") || type.includes("cross-site scripting")) {
          summary.xss += 1;
        }
        return summary;
      },
      { total: 0, sqli: 0, xss: 0 }
    );
  }, [result]);

  // Start Scanning Action
  async function handleStartScan(event) {
    if (event) event.preventDefault();
    setError("");
    setResult(null);
    setSelectedId(null);
    setAiReportReady(false);
    setIsAiGenerating(false);
    setAiReportMessage("");

    // Transition: Setup -> Scanning
    setActiveScreen("scanning");
    setProgress(0);

    try {
      const scan = await startScan({
        target_url: targetUrl,
        scan_type: scanType,
        rate_limit: Number(rateLimit),
      });

      if (isMockApi) {
        for (const [index, step] of scanSteps.entries()) {
          setCurrentStep(step);
          setProgress(Math.round(((index + 1) / scanSteps.length) * 100));
          await wait(600);
        }
      } else {
        let status = await getScanStatus(scan.scan_id);
        while (status.status === "running" || status.status === "queued") {
          setCurrentStep(status.current_step || status.stage || "스캔 진행 중");
          setProgress(Number(status.progress || 0));
          await wait(1000);
          status = await getScanStatus(scan.scan_id);
        }

        if (status.status === "failed") {
          throw new Error(status.error || "스캔이 실패했습니다.");
        }

        setCurrentStep(status.current_step || "스캔 완료");
        setProgress(100);
      }

      // Fetch scan result
      const scanResult = await getScanResult(scan.scan_id);
      const sortedVulnerabilities = [...scanResult.vulnerabilities].sort(
        (a, b) =>
          (severityRank[b.risk_level] || 0) - (severityRank[a.risk_level] || 0)
      );

      setResult({ ...scanResult, vulnerabilities: sortedVulnerabilities });
      setSelectedId(sortedVulnerabilities[0]?.id || null);
      setCurrentStep("스캔 완료");
      setAiReportReady(sortedVulnerabilities.some((item) => item.ai_report));
      setAiReportMessage(scanResult.report_status || "");

      // Transition: Scanning -> Dashboard
      setActiveScreen("dashboard");
    } catch (scanError) {
      setError(scanError.message);
      setCurrentStep("스캔 실패");
      setActiveScreen("setup");
    }
  }

  // Load a scan from the Archive list
  async function handleLoadArchiveScan(archiveItem) {
    setError("");
    setTargetUrl(archiveItem.target_url);
    
    if (isMockApi) {
      // Setup high quality mock result based on archive metadata
      const mockResult = {
        scan_id: archiveItem.scan_id,
        target_url: archiveItem.target_url,
        scan_time: archiveItem.scan_time,
        total_pages: archiveItem.risk_level === "High" ? 12 : 5,
        tested_inputs: archiveItem.risk_level === "High" ? 18 : 6,
        risk_level: archiveItem.risk_level,
        report_status: "AI 리포트 초안 생성",
        vulnerabilities: archiveItem.risk_level === "High" ? [
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
              vulnerability_summary: "id 파라미터에서 SQL Injection 가능성이 탐지되었습니다.",
              root_cause: "사용자 입력이 SQL 쿼리에 안전하게 바인딩되지 않고 동적으로 결합되어 실행되고 있습니다.",
              attack_scenario: "공격자는 조건식을 조작해 인증을 우회하고 데이터베이스 구조를 덤프할 수 있습니다.",
              secure_coding_guidance: "Prepared Statement 또는 Parameterized Query를 사용하여 사용자 입력을 바인딩 처리하십시오.",
              fixed_code_example: "SELECT * FROM users WHERE id = ? 형태의 파라미터 바인딩을 적용합니다.",
              validation_steps: "동일 payload로 재검사했을 때 데이터 누출이나 응답 차이가 유실되는지 재실험합니다.",
              disclaimer: "이 리포트는 자동 스캔 데이터를 바탕으로 자동 조립되었습니다. 실제 보완 작업 시 검토가 수반되어야 합니다.",
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
              vulnerability_summary: "name 파라미터에서 Reflected XSS 가능성이 탐지되었습니다.",
              root_cause: "입력된 매개변수가 HTML 템플릿에 출력되기 전 적절하게 이스케이프되지 않았습니다.",
              attack_scenario: "공격자가 조작된 피싱 URL을 사용자에게 유포하여 악성 스크립트를 세션 컨텍스트 내에서 실행시킬 수 있습니다.",
              secure_coding_guidance: "출력 컨텍스트에 맞춰 특수 문자를 HTML Entity 형태로 치환(Escaping)하십시오.",
              fixed_code_example: "htmlspecialchars($name, ENT_QUOTES, 'UTF-8') 형식의 필터를 거쳐 출력합니다.",
              validation_steps: "브라우저 콘솔에서 스크립트 실행이 차단되고 렌더링 결과에 특수 문자가 치환되어 출력되는지 검증합니다.",
              disclaimer: "클라이언트 사이드 환경과 Content Security Policy 규격에 따라 침투 가능 범위가 변경될 수 있습니다.",
            },
          }
        ] : []
      };

      setResult(mockResult);
      setSelectedId(mockResult.vulnerabilities[0]?.id || null);
      setActiveTab("scanner");
      setActiveScreen("dashboard");
      setAiReportReady(true);
      setAiReportMessage("AI 리포트 초안 생성");
      setIsAiGenerating(false);
      return;
    }

    try {
      const scanResult = await getScanResult(archiveItem.scan_id);
      setResult(scanResult);
      setSelectedId(scanResult.vulnerabilities[0]?.id || null);
      
      // Jump straight to Dashboard for scanner tab
      setActiveTab("scanner");
      setActiveScreen("dashboard");
      setAiReportReady(scanResult.vulnerabilities.some((item) => item.ai_report));
      setAiReportMessage(scanResult.report_status || "");
      setIsAiGenerating(false);
    } catch (loadError) {
      alert(`스캔 결과 로딩 실패: ${loadError.message}`);
    }
  }

  const fetchArchiveList = async () => {
    setLoadingArchive(true);
    try {
      const list = await getScanList();
      setArchiveList(list);
    } catch (err) {
      console.error("Failed to load archive scans:", err);
    } finally {
      setLoadingArchive(false);
    }
  };

  useEffect(() => {
    if (activeTab === "archive") {
      fetchArchiveList();
    }
  }, [activeTab]);

  return (
    <div className="app-shell">
      {/* 1. Left Sidebar Navigation Menu */}
      <aside className="sidebar">
        <div className="sidebar-container">
          <div className="sidebar-logo">
            <div className="sidebar-logo-glyph">S</div>
            <span className="sidebar-logo-text">Scaield</span>
          </div>

          <nav className="sidebar-menu" aria-label="사이드 메뉴">
            <button
              className={`sidebar-item ${activeTab === "scanner" ? "active" : ""}`}
              onClick={() => setActiveTab("scanner")}
              type="button"
            >
              <Activity size={18} />
              <span>보안 스캐너</span>
              {activeTab === "scanner" && <div className="sidebar-item-active-bar" />}
            </button>

            <button
              className={`sidebar-item ${activeTab === "archive" ? "active" : ""}`}
              onClick={() => setActiveTab("archive")}
              type="button"
            >
              <Folder size={18} />
              <span>리포트 보관함</span>
              {activeTab === "archive" && <div className="sidebar-item-active-bar" />}
            </button>

            <button
              className={`sidebar-item ${activeTab === "settings" ? "active" : ""}`}
              onClick={() => setActiveTab("settings")}
              type="button"
            >
              <Settings size={18} />
              <span>스캔 설정</span>
              {activeTab === "settings" && <div className="sidebar-item-active-bar" />}
            </button>

            <button
              className={`sidebar-item ${activeTab === "profile" ? "active" : ""}`}
              onClick={() => setActiveTab("profile")}
              type="button"
            >
              <User size={18} />
              <span>프로필</span>
              {activeTab === "profile" && <div className="sidebar-item-active-bar" />}
            </button>
          </nav>
        </div>

        <div className="sidebar-profile">
          <div className="sidebar-avatar">JH</div>
          <div className="sidebar-profile-info">
            <span className="sidebar-profile-name">jonghyun</span>
            <span className="sidebar-profile-role">
              <Zap size={11} /> Enterprise
            </span>
          </div>
        </div>
      </aside>

      {/* 2. Main Workspace Panel */}
      <main className="main-workspace">
        {/* Custom Gradient Mesh Backdrop */}
        <div className="gradient-mesh-backdrop" aria-hidden="true" />

        {/* Scanner Tab View */}
        {activeTab === "scanner" && (
          <div className="workspace-content">
            {/* Header Area */}
            <header className="content-header">
              <div className="content-header-title">
                <h2>Security Scanner</h2>
                <p>
                  {activeScreen === "setup" && "스캔 환경 구성을 세팅하고 자동화 진단을 실행합니다."}
                  {activeScreen === "scanning" && "DVWA 모의 환경 모의침투 테스트 및 정밀 크롤링을 수행하고 있습니다."}
                  {activeScreen === "dashboard" && "모의 진단 분석 결과 대시보드 리포트가 요약되었습니다."}
                  {activeScreen === "report" && "AI LLM 분석 엔진이 탐지된 근거를 종합하여 작성한 심층 리포트입니다."}
                </p>
              </div>

              {/* Navigation Back Buttons */}
              {activeScreen === "dashboard" && (
                <button
                  className="button-secondary-pill"
                  onClick={() => {
                    setActiveScreen("setup");
                    setResult(null);
                  }}
                  type="button"
                >
                  <ArrowLeft size={16} />
                  <span>메인 화면으로 돌아가기</span>
                </button>
              )}

              {activeScreen === "report" && (
                <div style={{ display: "flex", gap: "12px" }}>
                  <button
                    className="button-secondary-pill"
                    onClick={() => setActiveScreen("dashboard")}
                    type="button"
                  >
                    <ArrowLeft size={16} />
                    <span>대시보드로 돌아가기</span>
                  </button>
                  <button
                    className="button-secondary-pill"
                    onClick={() => {
                      setActiveScreen("setup");
                      setResult(null);
                    }}
                    type="button"
                  >
                    <ArrowLeft size={16} />
                    <span>메인 화면으로 돌아가기</span>
                  </button>
                </div>
              )}
            </header>

            {/* Screen State Machine */}
            {activeScreen === "setup" && (
              <div className="setup-grid animated-view">
                <section className="brand-intro">
                  <span className="eyebrow">LLM-Powered Vulnerability Scanner</span>
                  <h1>취약점 탐지부터 리포트까지 한 화면에서.</h1>
                  <p className="lead">
                    DVWA 기반 크롤링과 SQLi/XSS 펜테스트 결과를 개발자가 바로 읽을 수 있는 보안 리포트 형태로 요약 정리합니다.
                  </p>

                  {/* Faux Console Mockup */}
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
                        <span className="console-keyword">const</span> scanner = <span className="console-keyword">new</span> ScaieldScanner();
                      </div>
                      <div className="console-line">
                        scanner.setTarget(<span className="console-string">"{targetUrl}"</span>);
                      </div>
                      <div className="console-line">
                        scanner.addPayloads([<span className="console-string">"SQLi"</span>, <span className="console-string">"XSS"</span>]);
                      </div>
                      <div className="console-line">
                        <span className="console-comment">// Rate limits set to {rateLimit} reqs/sec</span>
                      </div>
                      <div className="console-line">
                        scanner.start();
                      </div>
                    </div>
                  </div>
                </section>

                {/* Form Setup Card */}
                <form className="setup-card" onSubmit={handleStartScan}>
                  <div className="form-group">
                    <label htmlFor="target-url-input">Target URL</label>
                    <div className="input-container">
                      <Globe2 size={16} />
                      <input
                        id="target-url-input"
                        className="text-input"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
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
                        onChange={(e) => setScanType(e.target.value)}
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
                        onChange={(e) => setRateLimit(e.target.value)}
                      />
                    </div>
                  </div>

                  {error && <p className="form-error" style={{ color: "var(--colors-error)", fontSize: "13px" }}>{error}</p>}

                  <div className="setup-card-footer">
                    <button className="button-primary-pill" type="submit">
                      <Play size={16} />
                      <span>모의 진단 및 취약점 스캔 시작</span>
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Scanning Console Screen (State 2: Scanning) */}
            {activeScreen === "scanning" && (
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

                {/* High fidelity current step active ticker */}
                <div className="scanning-active-ticker">
                  <div className="ticker-pulse" />
                  <span>{currentStep}</span>
                </div>

                <div className="scanning-progress-track">
                  <div className="scanning-progress-bar" style={{ width: `${progress}%` }} />
                </div>
              </div>
            )}

            {/* Results Dashboard Screen (State 3: Dashboard) */}
            {activeScreen === "dashboard" && (
              <div className="dashboard-grid animated-view">
                {/* AI Report Activation Banner */}
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
                            : aiReportMessage || "백엔드 AI 리포트 설정 후 다시 스캔하면 AI 리포트가 생성됩니다."}
                      </p>
                    </div>
                  </div>

                  <button
                    className="button-ai-cta"
                    disabled={!aiReportReady}
                    onClick={() => setActiveScreen("report")}
                    type="button"
                  >
                    <Sparkles size={16} />
                    <span>AI Report 보러가기</span>
                  </button>
                </div>

                {/* Metric Statistics Cards */}
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
                    <strong className="metric-value" style={{ color: result?.risk_level === "High" ? "var(--colors-ruby)" : "var(--colors-ink)" }}>
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
                    <span className="metric-detail">{result?.total_pages || 0}개의 모의 사이트 페이지 수집</span>
                  </article>
                </div>

                {/* Dashboard layout (Left: Vuln List, Right: Console Details) */}
                <div className="dashboard-composite">
                  <section className="vuln-list-panel">
                    <div className="vuln-list-header">취약점 탐지 내역 목록</div>
                    
                    {result?.vulnerabilities?.length > 0 ? (
                      result.vulnerabilities.map((item) => (
                        <button
                          key={item.id}
                          className={`vuln-item-btn ${selectedVulnerability?.id === item.id ? "selected" : ""}`}
                          onClick={() => setSelectedId(item.id)}
                          type="button"
                        >
                          <div className="vuln-item-info">
                            <span className="vuln-item-title">{item.type}</span>
                            <span className="vuln-item-path">{item.endpoint}</span>
                          </div>
                          <span className={`risk-badge ${item.risk_level.toLowerCase()}`}>{item.risk_level}</span>
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

                  {/* Vulnerability details in faux-IDE navy panel */}
                  <section className="detail-panel">
                    {selectedVulnerability ? (
                      <>
                        <div className="detail-panel-header">
                          <div className="detail-panel-title">
                            <h3>{selectedVulnerability.type}</h3>
                            <p>발견 고유 번호: {selectedVulnerability.id}</p>
                          </div>
                          <span className={`risk-badge ${selectedVulnerability.risk_level.toLowerCase()}`}>{selectedVulnerability.risk_level}</span>
                        </div>

                        <div className="detail-table">
                          <div className="detail-table-row">
                            <span className="detail-table-label">발견 위치 (Endpoint)</span>
                            <span className="detail-table-value">{selectedVulnerability.endpoint}</span>
                          </div>

                          <div className="detail-table-row">
                            <span className="detail-table-label">취약 매개변수 (Param)</span>
                            <span className="detail-table-value">{selectedVulnerability.parameter}</span>
                          </div>

                          <div className="detail-table-row">
                            <span className="detail-table-label">인젝션 Payload</span>
                            <span className="detail-table-value payload-code">{selectedVulnerability.payload}</span>
                          </div>

                          <div className="detail-table-row">
                            <span className="detail-table-label">탐지 방식</span>
                            <span className="detail-table-value">{selectedVulnerability.detection_method}</span>
                          </div>

                          <div className="detail-table-row">
                            <span className="detail-table-label">탐지 근거</span>
                            <span className="detail-table-value">{selectedVulnerability.evidence}</span>
                          </div>
                        </div>

                        <div className="detail-panel-actions">
                          <button
                            className="button-secondary-pill button-secondary-dark"
                            onClick={() => {
                              setActiveScreen("setup");
                              setResult(null);
                            }}
                            type="button"
                          >
                            <RefreshCw size={14} />
                            <span>재스캔 수행</span>
                          </button>
                        </div>
                      </>
                    ) : (
                      <div className="empty-state-card" style={{ height: "100%", justifyContent: "center" }}>
                        <AlertTriangle size={32} />
                        <h4>데이터 부재</h4>
                        <p>선택된 취약점의 세부 명세가 없습니다.</p>
                      </div>
                    )}
                  </section>
                </div>
              </div>
            )}

            {/* AI Security Report Screen (State 4: Report) */}
            {activeScreen === "report" && selectedVulnerability?.ai_report && (
              <div className="report-view animated-view">
                <div className="report-header-panel">
                  <div className="report-header-left">
                    <h1>AI Deep Security Report</h1>
                    <p>
                      대상 호스트 URL: <strong className="tnum">{targetUrl}</strong> · 취약점 유형: {selectedVulnerability.type}
                    </p>
                  </div>

                  <div className="report-action-buttons">
                    <button
                      className="button-secondary-pill"
                      onClick={() => window.print()}
                      type="button"
                    >
                      <Download size={16} />
                      <span>PDF 리포트 다운로드</span>
                    </button>
                  </div>
                </div>

                <div className="report-grid">
                  <section className="report-section">
                    <div className="report-section-title">
                      <ShieldAlert size={18} />
                      <span>취약점 발견 요약</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.vulnerability_summary}</p>
                  </section>

                  <section className="report-section">
                    <div className="report-section-title">
                      <Code size={18} />
                      <span>발생 원인 (Root Cause)</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.root_cause}</p>
                  </section>

                  <section className="report-section">
                    <div className="report-section-title">
                      <Zap size={18} />
                      <span>위험성 및 공격 시나리오</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.attack_scenario}</p>
                  </section>

                  <section className="report-section">
                    <div className="report-section-title">
                      <Database size={18} />
                      <span>안전한 코딩 수칙 가이드라인</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.secure_coding_guidance}</p>
                  </section>

                  {/* Dark featured band style for fixed code example */}
                  <section className="report-section code-highlight">
                    <div className="report-section-title">
                      <Code size={18} />
                      <span>보안 결함 수정 소스코드 예시</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.fixed_code_example}</p>
                  </section>

                  <section className="report-section">
                    <div className="report-section-title">
                      <Activity size={18} />
                      <span>보안 조치 재검증 절차</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.validation_steps}</p>
                  </section>

                  {/* Feature Band warm cream interlude for disclaimer */}
                  <section className="report-section report-disclaimer">
                    <div className="report-section-title">
                      <AlertTriangle size={18} />
                      <span>보안 권고 면책 조항</span>
                    </div>
                    <p>{selectedVulnerability.ai_report.disclaimer}</p>
                  </section>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Archive Tab View */}
        {activeTab === "archive" && (
          <div className="workspace-content">
            <header className="content-header">
              <div className="content-header-title">
                <h2>리포트 보관함 (Scan Archive)</h2>
                <p>이전에 진단한 웹 취약점 진단 이력을 불러와 결과를 신속히 재현하고 분석합니다.</p>
              </div>
            </header>

            <div className="sub-panel-view animated-view">
              <h3>과거 취약점 모의 스캔 리스트</h3>
              
              {loadingArchive ? (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "80px 40px", gap: "16px" }}>
                  <RefreshCw className="spin-loader" size={32} style={{ color: "var(--colors-primary)" }} />
                  <span style={{ fontSize: "14px", color: "var(--colors-ink-mute)" }}>보관된 리포트를 불러오는 중...</span>
                </div>
              ) : archiveList.length > 0 ? (
                <div className="archive-grid">
                  {archiveList.map((archiveItem) => (
                    <div
                      key={archiveItem.scan_id}
                      className="archive-card"
                      onClick={() => handleLoadArchiveScan(archiveItem)}
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
                    </div>
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
        )}

        {/* Settings Tab View */}
        {activeTab === "settings" && (
          <div className="workspace-content">
            <header className="content-header">
              <div className="content-header-title">
                <h2>Scan Settings</h2>
                <p>스캐너의 분석 크롤링 레벨, HTTP 헤더 인증 매개변수 및 성능 규격을 조정합니다.</p>
              </div>
            </header>

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
                      onChange={(e) => setScanDepth(Number(e.target.value))}
                    >
                      <option value={1}>1단계 (단일 홈페이지만 진단)</option>
                      <option value={2}>2단계 (서브도메인 한정)</option>
                      <option value={3}>3단계 (기본 하위 디렉토리)</option>
                      <option value={5}>5단계 (정밀 분석 깊이)</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label htmlFor="session-cookie-input">대상 모의환경 인증용 Session Cookie 값</label>
                    <input
                      id="session-cookie-input"
                      className="text-input"
                      style={{ paddingLeft: "16px" }}
                      value={sessionCookie}
                      onChange={(e) => setSessionCookie(e.target.value)}
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
                      onChange={(e) => setCustomHeader(e.target.value)}
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

              {/* Right Side: Request Simulation Console */}
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
                      <span className="console-keyword">GET</span> <span className="console-string">/dvwa/vulnerabilities/sqli/ HTTP/1.1</span>
                    </div>
                    <div className="console-line">
                      <span className="console-keyword">Host:</span> <span className="console-string">{targetDomain}</span>
                    </div>
                    <div className="console-line">
                      <span className="console-keyword">User-Agent:</span> <span className="console-string">Scaield-Vulnerability-Engine/1.2 (LLM-Powered)</span>
                    </div>
                    {sessionCookie && (
                      <div className="console-line">
                        <span className="console-keyword">Cookie:</span> <span className="console-string">{sessionCookie}</span>
                      </div>
                    )}
                    {customHeaderParsed && (
                      <div className="console-line">
                        <span className="console-keyword">{customHeaderParsed.name}:</span> <span className="console-string">{customHeaderParsed.value}</span>
                      </div>
                    )}
                    <div className="console-line">
                      <span className="console-comment">// Max Crawl Depth: {scanDepth} stages</span>
                    </div>
                    <div className="console-line">
                      <span className="console-keyword">Accept:</span> <span className="console-string">text/html,application/xhtml+xml,application/xml;q=0.9</span>
                    </div>
                    <div className="console-line">
                      <span className="console-keyword">Connection:</span> <span className="console-string">keep-alive</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Profile Tab View */}
        {activeTab === "profile" && (
          <div className="workspace-content">
            <header className="content-header">
              <div className="content-header-title">
                <h2>Developer Profile</h2>
                <p>스캐너 사용 주체의 인증 자격 상태 및 API 접근 크레덴셜을 열람합니다.</p>
              </div>
            </header>

            <div className="profile-layout animated-view">
              {/* Left Column: Glassmorphic Scaield ID Card */}
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
                  <div style={{ fontSize: "14px", color: "var(--colors-magenta)", fontWeight: "500", letterSpacing: "-0.2px" }}>
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

              {/* Right Column: Credentials & Usage Stats */}
              <div className="profile-right-panels">
                {/* Credentials Card */}
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
                      <label htmlFor="api-token-input">Administrator API Token (Masked)</label>
                      <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                        <input
                          id="api-token-input"
                          className="text-input"
                          style={{ paddingLeft: "16px", fontFamily: "monospace", fontSize: "12px" }}
                          value="sc_live_••••••••••••••••3ae4"
                          readOnly
                        />
                        <button
                          className="button-secondary-pill"
                          style={{ position: "absolute", right: "6px", height: "32px", fontSize: "11px" }}
                          onClick={() => {
                            navigator.clipboard.writeText("sc_live_45aefb68d901c234a98b76543ae4");
                            alert("클라이언트 API Token 복사 완료");
                          }}
                          type="button"
                        >
                          복사
                        </button>
                      </div>
                    </div>

                    <span style={{ fontSize: "11.5px", color: "var(--colors-ink-mute)", lineHeight: "1.4" }}>
                      💡 실제 API key나 비밀값은 프론트엔드 환경변수에 직접 넣지 말고, 반드시 백엔드 미들웨어에서 거쳐 관리하도록 설정하는 것을 권장합니다.
                    </span>
                  </div>
                </div>

                {/* Usage Stats Card */}
                <div className="sub-panel-view" style={{ padding: "32px" }}>
                  <h3>이번 달 플랜 사용 통계</h3>
                  
                  <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "8px" }}>
                    <div className="stat-item">
                      <div className="stat-item-header">
                        <span className="stat-label">모의 취약점 진단 횟수</span>
                        <span className="stat-value tnum">45 / 무제한</span>
                      </div>
                      <div className="stat-progress-bar">
                        <div className="stat-progress-fill" style={{ width: "100%" }} />
                      </div>
                    </div>

                    <div className="stat-item">
                      <div className="stat-item-header">
                        <span className="stat-label">AI 리포트 생성 건수</span>
                        <span className="stat-value tnum">128 / 무제한</span>
                      </div>
                      <div className="stat-progress-bar">
                        <div className="stat-progress-fill" style={{ width: "100%" }} />
                      </div>
                    </div>

                    <div className="stat-item">
                      <div className="stat-item-header">
                        <span className="stat-label">동시 최대 스캔 속도 (Rate Limit Limit)</span>
                        <span className="stat-value tnum">30 req/s (최대 지원 속도)</span>
                      </div>
                      <div className="stat-progress-bar">
                        <div className="stat-progress-fill" style={{ width: "100%" }} />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Global Footer (Visible inside workspace unless printing) */}
        <footer
          style={{
            marginTop: "auto",
            padding: "24px 48px",
            borderTop: "1px solid var(--colors-hairline)",
            backgroundColor: "rgba(255, 255, 255, 0.6)",
            backdropFilter: "blur(8px)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: "12px",
            color: "var(--colors-ink-mute)",
            flexShrink: 0
          }}
        >
          <span>© 2026 Scaield Security Platform. All rights reserved.</span>
          <span style={{ display: "flex", gap: "16px" }}>
            <a href="#privacy" style={{ textDecoration: "none" }}>Privacy Policy</a>
            <a href="#terms" style={{ textDecoration: "none" }}>Terms of Service</a>
          </span>
        </footer>
      </main>
    </div>
  );
}

function wait(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export default App;
