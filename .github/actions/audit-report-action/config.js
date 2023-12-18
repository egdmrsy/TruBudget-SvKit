const core = require('@actions/core');
const github = require('@actions/github');

export const Config = {
  projects: core.getInput('projects').split(','),
  includeDevDependencies: core.getInput('include-dev-dependencies') === 'true',
  includeUnfixedForImage: core.getInput('include-unfixed-for-image') === 'true',
  includeUnfixedForFs: core.getInput('include-unfixed-for-fs') === 'true',
  severityLevelsForImage: core.getInput('severity-levels-for-image') || "CRITICAL,HIGH,MEDIUM",
  severityLevelsForFs: core.getInput('severity-levels-for-fs') || "CRITICAL,HIGH,MEDIUM,LOW",
  token: core.getInput('token'),
  issueTitlePrefix: core.getInput('issue_title_prefix') || 'Security Report:',
  octokit: github.getOctokit(core.getInput('token')),
  repo: github.context.repo,
  spawnProcessBufferSize: 10485760 // 10MB
};


export function validateConfig() {
  const { projects, severityLevels, token } = Config;

  if (!projects) {
    throw new Error('Input project names are required');
  }

  if (!token) {
    throw new Error('Input token is required');
  }
}