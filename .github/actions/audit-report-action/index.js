const core = require('@actions/core');
const github = require('@actions/github');
const child_process = require('child_process');

const SPAWN_PROCESS_BUFFER_SIZE = 10485760

const run = async function() {
  const projects = core.getInput('projects').split(',');
  if(!projects) {
    throw new Error('Project names are required');
  }
  const vulnerabilityProjectMapping = new Map();
  const discoveredVulnerabilities = [];
  for(const projectName of projects) {
    const vulnerabilities = await runAudit(projectName);

    for(const vulnerability of vulnerabilities) {
      const vId = vulnerability.via[0].source;

      if(!vulnerabilityProjectMapping.has(vId)){
        discoveredVulnerabilities.push(vulnerability);
        vulnerabilityProjectMapping.set(vId,[projectName]);
      } else {
        const addedProjectNames = vulnerabilityProjectMapping.get(vId);
        addedProjectNames.push(projectName);
        vulnerabilityProjectMapping.set(vId, addedProjectNames);
      }
    }
  }

  await createOrUpdateIssues(vulnerabilityProjectMapping, discoveredVulnerabilities);
  return true;
}

async function runAudit(projectName) {
  core.info(`\n Auditing ${projectName}...`);
  if (!projectName) {
    throw new Error('A project name is required');
  }
  process.chdir(projectName);

  let result = child_process.spawnSync("npm", ["ci", "--no-audit", "--legacy-peer-deps"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  result = child_process.spawnSync("npm", ["audit", "--json", "--omit=dev"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  const auditRawJson = JSON.parse(result.stdout);
  let vulnerabilities = [];
  if (auditRawJson.metadata?.vulnerabilities?.total > 0) {
    core.info("Vulnerabilities found");
    vulnerabilities = extractVulnerabilities(auditRawJson.vulnerabilities);
  } else {
    core.info("No vulnerabilities found");
  }
  process.chdir("..");
  return vulnerabilities;
}

async function createOrUpdateIssues(vulnerabilityProjectMapping, discoveredVulnerabilities) {
  const token = core.getInput('token');
  const octokit = github.getOctokit(token);

  // Get all security issues
  const { data: securityIssues} = await octokit.rest.issues.listForRepo(
    {
      ...github.context.repo,
      state: 'open',
      labels: ['security']
    }
  )

  const vulnerabilityIssues = securityIssues
    .filter(issue => issue.title.includes("Vulnerability Report:"));

  // Clean up old issues if Vulnerability is not mentioned.
  await closeOldIssues(octokit.rest.issues.update, vulnerabilityIssues, vulnerabilityProjectMapping);

  for(const vulnerability of discoveredVulnerabilities) {
    const vId = vulnerability.via[0].source;
    const vName = vulnerability.via[0].name;
    const issueTitle = `Vulnerability Report: ${vId} - ${vName}`;

    const issue = vulnerabilityIssues
    .filter(issue => issue.title === issueTitle)
    .shift();
    vulnerabilityIssues.forEach(v => core.info(JSON.stringify(v)));

    if (issue) {
      // issue exists
      // update the issue
      const issueNumber = issue.number;
      const issueBody = issue.body_html;
      core.info(issue.body_html);
      core.info(issue.body_text);
      await octokit.rest.issues.update({
        ...github.context.repo,
        issue_number: issueNumber,
        body: issueBody
      });
    } else {
      // create new issue
      const affectedProjects = vulnerabilityProjectMapping.get(vId);
      await createNewIssue(octokit.rest.issues.create, vId, vName, vulnerability.via[0].title, vulnerability.via[0].severity, vulnerability.via[0].url, vulnerability.effects, affectedProjects, issueTitle);
    }
  }
}

async function createNewIssue(createFunc, vId, vName, vTitle, vSeverity, vUrl, vEffects, affectedProjects, issueTitle) {
  let newIssueBody = `\
    <h2 id="last-checked-date-">Last checked date:</h2>
    <p>${new Date(Date.now()).toLocaleDateString()}</p>
    <h2 id="vulnerability-information">Vulnerability Information</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Title</th>
          <th>Severity</th>
          <th>URL</th>
          <th>Effects</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>${vId}</td>
          <td>${vName}</td>
          <td>${vTitle}</td>
          <td>${vSeverity}</td>
          <td>${vUrl}</td>
          <td>${vEffects}</td>
        </tr>
      </tbody>
    </table>
    <h2 id="affected-projects">Affected Projects</h2>
    `
  newIssueBody = newIssueBody.concat("<ul>");
  for(const affectedProject of affectedProjects) {
    newIssueBody = newIssueBody.concat(`<li>${affectedProject}</li>`);
  }
  newIssueBody = newIssueBody.concat("</ul>");

  await createFunc({
    ...github.context.repo,
    title: issueTitle,
    body: newIssueBody,
    labels: ["security"]
  });

}

async function closeOldIssues(updateFunc, vulnerabilityIssues, vulnerabilityProjectMapping) {
  for(const vulnerabilityIssue of vulnerabilityIssues) {
    const issueVId = Number(vulnerabilityIssue.title.split(": ")[1].split(" - ")[0]);
    if(!vulnerabilityProjectMapping.has(issueVId)){
      // There is an open issue 
      await updateFunc({
        ...github.context.repo,
        issue_number: vulnerabilityIssue.number,
        state: 'closed'
      })
    }
  }
}

function extractVulnerabilities(resultJsonVulnerabilities) {
  return Object.entries(resultJsonVulnerabilities).map(([key, value]) => {
    if (!value.isDirect) {
      return value;
    }
  }).filter((value) => { return !!value; });
}

run();