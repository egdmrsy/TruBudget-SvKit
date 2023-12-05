import { Config } from './config';
import { buildImage, cleanupImage } from './docker';
import child_process from 'child_process';

export async function runContainerAudit(projectName) {
  const imageName = `docker.io/${projectName}:local`;

  console.info(`\n Building Docker Image ${imageName}...`);

  await buildImage(imageName, projectName, `./${projectName}`);

  console.info(`\nAuditing image ${imageName}...`);

  const additionalArgs = ["image", `docker.io/${projectName}:${Config.sha}`,"--format", "template", "template", "@./.github/actions/audit-report-action/htmltemp.tpl", "--exit-code", "1", "--vuln-type", "os", "--severity", "CRITICAL,HIGH,MEDIUM,LOW"];
  if (!Config.includeUnfixed) {
    options.push("--ignore-unfixed");
  }

  const result = child_process.spawnSync("trivy", additionalArgs, {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });

  console.log(result.stdout);

  await cleanupImage(imageName);
}


export async function runAudit(projectName) {
  if (!projectName) {
    throw new Error('A project name is required');
  }

  console.info(`\nAuditing ${projectName}...`);

  process.chdir(projectName);

  child_process.spawnSync("npm", ["ci", "--no-audit", "--legacy-peer-deps"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  const result = child_process.spawnSync("npm", ["audit", "--json", "--omit=dev"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

  const auditRaw = JSON.parse(result.stdout);
  let vulnerabilityList = [];

  if (auditRaw.metadata?.vulnerabilities?.total > 0) {
    console.info("Vulnerabilities found");
    vulnerabilityList = extractVulnerabilities(auditRaw.vulnerabilities);
  } else {
    console.info("No vulnerabilities found");
  }

  process.chdir("..");

  return vulnerabilityList;
}


function extractVulnerabilities(rawVulnerabilities) {
  return Object.values(rawVulnerabilities).filter(value => {
    return !value.isDirect && Array.isArray(value.via) && typeof value.via[0] === 'object';
  });
}