import { Config } from './config';
import { buildImage, cleanupImage } from './docker';
import child_process from 'child_process';

export async function performImageAudit(projectName) {
  const imageName = `docker.io/${projectName}:local`;

  console.info(`\nBuilding Docker Image ${imageName}...`);

  await buildImage(imageName, projectName, `./${projectName}`);

  console.info(`\n Performing Image audit on image ${imageName}...`);

  const additionalArgs = ["image", imageName, "--format", "json", "--exit-code", "1", "--vuln-type", "os"];
  additionalArgs.push("--severity", Config.severityLevels);

  if (!Config.includeUnfixed) {
    additionalArgs.push("--ignore-unfixed");
  }

  const result = child_process.spawnSync("trivy", additionalArgs, {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });

  await cleanupImage(imageName);

  return result.stdout;
}

export async function performFsAudit(projectName) {
  console.info(`\n Performing File System audit on Project ${projectName}...`);

  const additionalArgs = ["fs", `./${projectName}`, "--format", "json", "--exit-code", "1"];
  additionalArgs.push("--severity", Config.severityLevels);

  if (Config.includeDevDependencies) {
    additionalArgs.push("--include-dev-deps");
  }

  if (!Config.includeUnfixed) {
    additionalArgs.push("--ignore-unfixed");
  }

  const result = child_process.spawnSync("trivy", additionalArgs, {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });

  const outputJSON = JSON.parse(result.stdout);
  if(outputJSON.Results && outputJSON.Results.length > 0 && outputJSON.Results[0].Vulnerabilities && outputJSON.Results[0].Vulnerabilities.length > 0) {
    return outputJSON.Results[0].Vulnerabilities.map(value => {
      return {
        id: value.VulnerabilityID, 
        packageName: value.PkgName, 
        status: value.Status, 
        title: value.Title, 
        severity: value.Severity,
        fixedVersion: value.FixedVersion,
        links: value.References,
        publishedDate: value.PublishedDate
        }
    });
  }
  return [];
}