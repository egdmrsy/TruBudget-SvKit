const core = require('@actions/core');
const github = require('@actions/github');
const child_process = require('child_process');

const SPAWN_PROCESS_BUFFER_SIZE = 10485760
core.info(core.getInput("projects"));
core.info(core.getInput("token"));

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
      const vId = vulnerability.via.source;

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
  console.log(`Auditing ${projectName}...`);
  if (!projectName) {
    throw new Error('A project name is required');
  }
  process.chdir(projectName);
  core.info(`Current working directory: ${process.cwd()}`);

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
    const vId = vulnerability.via.source;
    const vName = vulnerability.via.name;
    const issueTitle = `Vulnerability Report: ${vId} - ${vName}`;

    const issue = vulnerabilityIssues
    .filter(issue => issue.title === issueTitle)
    .shift();

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
      await createNewIssue(octokit.rest.issues.create, vId, vName, vulnerability.via.title, vulnerability.via.severity, vulnerability.via.url, vulnerability.effects, affectedProjects, issueTitle);
    }
  }
}

async function createNewIssue(createFunc, vId, vName, vTitle, vSeverity, vUrl, vEffects, affectedProjects, issueTitle) {
  const newIssueBody = `\
    ## Last checked date: \
    ${new Date(Date.now()).toLocaleDateString()} \
    \
    ## Vulnerability Information\
    | ID | Name | Title | Severity | URL | Effects | \
    | -- | ---- | ----- | -------- | --- | ------- | \
    | ${vId}| ${vName} | ${vTitle} | ${vSeverity} | ${vUrl} | ${vEffects}\
  
    \
    ## Affected Projects\
    `
  for(const affectedProject of affectedProjects) {
    newIssueBody.concat(`- ${affectedProject} \n`);
  }

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