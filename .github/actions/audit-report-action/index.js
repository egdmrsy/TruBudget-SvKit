const core = require('@actions/core');
const github = require('@actions/github');
const child_process = require('child_process');
const { extractVulnerabilities } = require('./utils');
const { createOrUpdateIssues } = require('./issue');

const SPAWN_PROCESS_BUFFER_SIZE = 10485760

const run = async function() {
  const projects = core.getInput('projects').split(',');
  if(!projects) {
    throw new Error('Project names are required');
  }

  const vulnerabilityIdProjectMapping = new Map();
  const activeVulnerabilities = [];

  for(const projectName of projects) {
    const projectVulnerabilities = await runAudit(projectName);

    for(const projectVulnerability of projectVulnerabilities) {
      const vId = projectVulnerability.via[0].source;
      if(vulnerabilityIdProjectMapping.has(vId)){
        const addedProjectNames = vulnerabilityIdProjectMapping.get(vId);
        addedProjectNames.push(projectName);
        vulnerabilityIdProjectMapping.set(vId, addedProjectNames);
      } else {
        activeVulnerabilities.push(projectVulnerability);
        vulnerabilityIdProjectMapping.set(vId,[projectName]);
      }
    }
  }
  const token = core.getInput('token');
  const octokit = github.getOctokit(token);
  await createOrUpdateIssues(octokit, github.context.repo, vulnerabilityIdProjectMapping, activeVulnerabilities);
  return true;
}

async function runAudit(projectName) {
  core.info(`\n Auditing ${projectName}...`);
  if (!projectName) {
    throw new Error('A project name is required');
  }
  process.chdir(projectName);

  child_process.spawnSync("npm", ["ci", "--no-audit", "--legacy-peer-deps"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  const result = child_process.spawnSync("npm", ["audit", "--json", "--omit=dev"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  const auditRawJson = JSON.parse(result.stdout);
  let vulnerabilityList = [];

  if (auditRawJson.metadata?.vulnerabilities?.total > 0) {
    core.info("Vulnerabilities found");
    vulnerabilityList = extractVulnerabilities(auditRawJson.vulnerabilities);
  } else {
    core.info("No vulnerabilities found");
  }
  process.chdir("..");
  return vulnerabilityList;
}
run();