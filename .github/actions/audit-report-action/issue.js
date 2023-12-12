import { Config } from "./config";
import { parse } from 'node-html-parser';

const octokit = Config.octokit;
const repo = Config.repo;
const issueTitlePrefix = Config.issueTitlePrefix;

export async function createOrUpdateIssues(vulnerabilityIdProjectMapping, activeVulnerabilities, type) {
  // Get all security labeled open issues
  const { data: securityOpenIssues } = await octokit.rest.issues.listForRepo({
    ...repo,
    state: 'open',
    labels: ['security']
  });

  const issueTitle = type === "fs" ? `${issueTitlePrefix} Project Vulnerabilities`: `${issueTitlePrefix} Image Vulnerabilities`;
  const vulnerabilityIssue = securityOpenIssues.find(issue => issue.title === issueTitle);

  if(vulnerabilityIssue && activeVulnerabilities > 0) {
    await updateExistingIssue(vulnerabilityIssue, vulnerabilityIdProjectMapping);
  } 
  else if(vulnerabilityIssue && activeVulnerabilities == 0) {
    await closeIssue(vulnerabilityIssue.number);
  }
  else {
    console.info(activeVulnerabilities);
    await createNewIssue(activeVulnerabilities, vulnerabilityIdProjectMapping, issueTitle);
  }

 
}

async function updateExistingIssue(vulnerabilityIssue, vulnerabilities, vulnerabilityIdProjectMapping) {
  const issueNumber = vulnerabilityIssue.number;
  const root = parse(vulnerabilityIssue.body);
  let newBody = "";
  root.querySelector('#last-scan-date').set_content("test");
  newBody = root.toString();
  /*let issueBody = vulnerabilityIssue.body.replace(/[0-9]{1,2}\/[0-9]{1,2}\/[0-9]{4}/gm, new Date(Date.now()).toLocaleDateString());
  let appendClosingListTag = false;

  for (const affectedProject of affectedProjects) {
    const element = `<li>${affectedProject}</li>`;
    if (!issueBody.includes(element)) {
      issueBody = issueBody.replace(/\<\/ul\>/gm, element);
      appendClosingListTag = true;
    }
  }*/
  await octokit.rest.issues.update({
    ...repo,
    issue_number: issueNumber,
    body: newBody
  });
}

async function createNewIssue(vulnerabilities, vulnerabilityIdProjectMapping, issueTitle) {
 
  let rows = '';
  for(const vulnerability of vulnerabilities) {
    if(vulnerability.links && Array.isArray(vulnerability.links) && vulnerability.links.length > 0) {
      const row = `<tr><td>${vulnerability.id}</td><td>${vulnerability.packageName}</td><td>${vulnerability.title}</td><td>${vulnerability.severity}</td><td>${vulnerability.status}</td><td>${vulnerability.fixedVersion}</td><td>${vulnerability.publishedDate}</td><td><ul>${vulnerabilityIdProjectMapping.get(vulnerability.id).map(project => `<li>${project}</li>`).join("")}</ul></td><td><ul>${vulnerability.links.filter(link => link.includes("GHSA" || "nvd")).map(link => `<li><a href="${link}">${link}</a></li>`).join('')}</ul></td></tr>`;
      rows = rows.concat(row);
    }
  }
  const newIssueBody = `<h2 id="last-scan-date">Last scan date</h2>
    <p>${new Date(Date.now()).toLocaleDateString()}</p>
    <h2 id="vulnerability-header">Present Vulnerabilities</h2>
    <table>
      <thead>
        <tr>
          <th>Vulnerability ID</th>
          <th>PkgName</th>
          <th>Title</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Fixed Version</th>
          <th>Published Date</th>
          <th>Affects</th>
          <th>Links</th>
        </tr>
      </thead>
      <tbody>
       ${rows}
      </tbody>
    </table>`;

  await octokit.rest.issues.create({
    ...repo,
    title: issueTitle,
    body: newIssueBody,
    labels: ["security"]
  });
}

async function closeIssue(issueNumber) {
  await octokit.rest.issues.update({ ...repo, issue_number: issueNumber, state: 'closed' });
}