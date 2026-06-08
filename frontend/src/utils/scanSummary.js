export function getVulnerabilityCounts(vulnerabilities = []) {
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
    { total: 0, sqli: 0, xss: 0 },
  );
}
