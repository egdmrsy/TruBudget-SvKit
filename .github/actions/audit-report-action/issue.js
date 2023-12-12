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

  const issueTitle = type === "fs" ? `${issueTitlePrefix} Project Vulnerabilities` : `${issueTitlePrefix} Image Vulnerabilities`;

  const vulnerabilityIssue = securityOpenIssues.find(issue => issue.title === issueTitle);
  if(vulnerabilityIssue && activeVulnerabilities.length > 0) {
    await updateExistingIssue(vulnerabilityIssue, vulnerabilityIdProjectMapping);
  } 
  else if(vulnerabilityIssue && activeVulnerabilities.length == 0) {
    await closeIssue(vulnerabilityIssue.number);
  }
  else {
    await createNewIssue(activeVulnerabilities, vulnerabilityIdProjectMapping, issueTitle);
  }

 
}

async function updateExistingIssue(vulnerabilityIssue, activeVulnerabilities, vulnerabilityIdProjectMapping) {
  const issueNumber = vulnerabilityIssue.number;
  const root = parse(vulnerabilityIssue.body);
  root.querySelector('#last-scan-date').set_content(new Date(Date.now()).toLocaleDateString());
  const currentIds = root.querySelectorAll('tr').filter(elem => elem.id && elem.id !== '').map(elem => elem.id);
  currentIds.forEach(id => {
    if(vulnerabilityIdProjectMapping.has(id)) {
      const affectedProjects = vulnerabilityIdProjectMapping.get(id);
      const projectParentList = root.querySelector(`#${id}-projects`);
      const children = projectParentList.childNodes;
      
      children.forEach(node => {
        if(!affectedProjects.includes(node.innerText)) {
          projectParentList.removeChild(node);
        }
      });
      const issueProjects = children.map(node => node.innerText);
      affectedProjects.forEach(proj => {
        if(!issueProjects.includes(proj)) {
          projectParentList.insertAdjacentHTML('beforeend', `<li>${proj}</li>`);
        }
      });
    } 
    else {
      root.querySelector(`#${id}`).remove();
    }
  });
  activeVulnerabilities.forEach(vulnerability => {
    if(!currentIds.includes(vulnerability.id)) {
      const row = `<tr id="${vulnerability.id}"><td>${vulnerability.id}</td><td>${vulnerability.packageName}</td><td>${vulnerability.title}</td><td>${vulnerability.severity}</td><td>${vulnerability.status}</td><td>${vulnerability.fixedVersion}</td><td>${vulnerability.publishedDate}</td><td><ul id="${vulnerability.id}-projects">${vulnerabilityIdProjectMapping.get(vulnerability.id).map(project => `<li>${project}</li>`).join("")}</ul></td><td><ul>${vulnerability.links.filter(link => link.includes("GHSA" || "nvd")).map(link => `<li><a href="${link}">${link}</a></li>`).join('')}</ul></td></tr>`;
      const parent = root.querySelector("#table-body");
      parent.insertAdjacentHTML('beforeend', row);
    }
  });

  await octokit.rest.issues.update({
    ...repo,
    issue_number: issueNumber,
    body: root.toString()
  });
}

async function createNewIssue(vulnerabilities, vulnerabilityIdProjectMapping, issueTitle) {
  const root = parse('');
  root.appendChild(parse('<h2>Last scan date</h2>'));
  root.appendChild(parse(`<p id="last-scan-date">${new Date(Date.now()).toLocaleDateString()}</p>`));
  root.appendChild(parse('<h2 id="vulnerability-header">Present Vulnerabilities</h2>'));
  root.appendChild(parse('<table></table>'));

  root.querySelector('table').appendChild(parse('<thead><tr><th>Vulnerability ID</th><th>PkgName</th><th>Title</th><th>Severity</th><th>Status</th><th>Fixed Version</th><th>Published Date</th><th>Affects</th><th>Links</th></tr></thead>'));
  const tableBody = table.insertAdjacentHTML('beforeend', '<tbody id="table-body"></tbody>');

  for(const vulnerability of vulnerabilities) {
    if(vulnerability.links && Array.isArray(vulnerability.links) && vulnerability.links.length > 0) {
      const row = tableBody.appendChild(parse(`<tr id="${vulnerability.id}"></tr>`));
      row.appendChild(parse(`<td>${vulnerability.id}</td>`));
      row.appendChild(parse(`<td>${vulnerability.id}</td>`));
      row.appendChild(parse(`<td>${vulnerability.packageName}</td>`));
      row.appendChild(parse(`<td>${vulnerability.title}</td>`));
      row.appendChild(parse(`<td>${vulnerability.severity}</td>`));
      row.appendChild(parse(`<td>${vulnerability.status}</td>`));
      row.appendChild(parse(`<td>${vulnerability.fixedVersion}</td>`));
      row.appendChild(parse(`<td>${vulnerability.publishedDate}</td>`));
      row.appendChild(parse(`<td><ul id="${vulnerability.id}-projects">${vulnerabilityIdProjectMapping.get(vulnerability.id).map(project => `<li>${project}</li>`).join("")}</ul></td>`));
      row.appendChild(parse(`<td><ul>${vulnerability.links.filter(link => link.includes("GHSA" || "nvd")).map(link => `<li><a href="${link}">${link}</a></li>`).join('')}</ul></td>`));
    }
  }

  await octokit.rest.issues.create({
    ...repo,
    title: issueTitle,
    body: root.toString(),
    labels: ["security"]
  });
}

async function closeIssue(issueNumber) {
  await octokit.rest.issues.update({ ...repo, issue_number: issueNumber, state: 'closed' });
}