export function extractVulnerabilities(resultJsonVulnerabilities) {
  return Object.entries(resultJsonVulnerabilities).map(([key, value]) => {
    if (!value.isDirect) {
      return value;
    }
  }).filter((value) => { return !!value; });
}