import { useMemo, useState } from "react";
import {
  getScanList,
  getScanResult,
  getScanStatus,
  isMockApi,
  startScan,
} from "../../../api/scans.js";
import {
  createMockArchiveResult,
  scanSteps,
  severityRank,
} from "../../../data/scannerData.js";
import { getVulnerabilityCounts } from "../../../utils/scanSummary.js";
import { wait } from "../../../utils/wait.js";

export function useScanner({ setActiveTab }) {
  const [activeScreen, setActiveScreen] = useState("setup");
  const [targetUrl, setTargetUrl] = useState("http://localhost:8080/dvwa");
  const [scanType, setScanType] = useState("all");
  const [rateLimit, setRateLimit] = useState(10);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState("대기 중");
  const [result, setResult] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [error, setError] = useState("");
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [aiReportReady, setAiReportReady] = useState(false);
  const [aiReportMessage, setAiReportMessage] = useState("");
  const [archiveList, setArchiveList] = useState([]);
  const [loadingArchive, setLoadingArchive] = useState(false);

  const selectedVulnerability = useMemo(() => {
    if (!result?.vulnerabilities?.length) {
      return null;
    }

    return (
      result.vulnerabilities.find((item) => item.id === selectedId) ||
      result.vulnerabilities[0]
    );
  }, [result, selectedId]);

  const counts = useMemo(
    () => getVulnerabilityCounts(result?.vulnerabilities || []),
    [result],
  );

  function resetToSetup() {
    setActiveScreen("setup");
    setResult(null);
  }

  async function handleStartScan(event) {
    if (event) event.preventDefault();

    setError("");
    setResult(null);
    setSelectedId(null);
    setAiReportReady(false);
    setIsAiGenerating(false);
    setAiReportMessage("");
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

      const scanResult = await getScanResult(scan.scan_id);
      const sortedVulnerabilities = [...(scanResult.vulnerabilities || [])].sort(
        (a, b) =>
          (severityRank[b.risk_level] || 0) - (severityRank[a.risk_level] || 0),
      );

      setResult({ ...scanResult, vulnerabilities: sortedVulnerabilities });
      setSelectedId(sortedVulnerabilities[0]?.id || null);
      setCurrentStep("스캔 완료");
      setAiReportReady(sortedVulnerabilities.some((item) => item.ai_report));
      setAiReportMessage(scanResult.report_status || "");
      setActiveScreen("dashboard");
    } catch (scanError) {
      setError(scanError.message);
      setCurrentStep("스캔 실패");
      setActiveScreen("setup");
    }
  }

  async function handleLoadArchiveScan(archiveItem) {
    setError("");
    setTargetUrl(archiveItem.target_url);

    if (isMockApi) {
      const mockResult = createMockArchiveResult(archiveItem);
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
      setSelectedId(scanResult.vulnerabilities?.[0]?.id || null);
      setActiveTab("scanner");
      setActiveScreen("dashboard");
      setAiReportReady(
        (scanResult.vulnerabilities || []).some((item) => item.ai_report),
      );
      setAiReportMessage(scanResult.report_status || "");
      setIsAiGenerating(false);
    } catch (loadError) {
      alert(`스캔 결과 로딩 실패: ${loadError.message}`);
    }
  }

  async function fetchArchiveList() {
    setLoadingArchive(true);
    try {
      const list = await getScanList();
      setArchiveList(list);
    } catch (err) {
      console.error("Failed to load archive scans:", err);
    } finally {
      setLoadingArchive(false);
    }
  }

  return {
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
    setResult,
    selectedVulnerability,
    selectedId,
    setSelectedId,
    counts,
    error,
    isAiGenerating,
    aiReportReady,
    aiReportMessage,
    archiveList,
    loadingArchive,
    handleStartScan,
    handleLoadArchiveScan,
    fetchArchiveList,
    resetToSetup,
  };
}
