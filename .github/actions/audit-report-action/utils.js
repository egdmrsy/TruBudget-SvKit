export function extractVulnerabilities(resultJsonVulnerabilities) {
  return Object.entries(resultJsonVulnerabilities).map(([key, value]) => {
    if (!value.isDirect && Array.isArray(value.via) && typeof value.via[0] == 'object') {
      return value;
    }
  }).filter((value) => { return !!value; });
}