const core = require('@actions/core');
const github = require('@actions/github');

export const Config = {
  projects: core.getInput('projects').split(','),
  includeDevDependencies: core.getInput('include-dev-dependencies') === 'true',
  includeUnfixed: core.getInput('include-unfixed') === 'true',
  severityLevels: core.getInput('severity-levels'),
  token: core.getInput('token'),
  issueTitlePrefix: core.getInput('issue_title_prefix') || 'Security Report:',
  octokit: github.getOctokit(core.getInput('token')),
  repo: github.context.repo,
  sha: github.sha,
  spawnProcessBufferSize: 10485760 // 10MB
};


export function validateConfig() {
  const { projects, severityLevels, token } = Config;

  if (!projects) {
    throw new Error('Input project names are required');
  }

  if (!severityLevels) {
    throw new Error('Input severity levels are required');
  }

  if (!token) {
    throw new Error('Input token is required');
  }
}