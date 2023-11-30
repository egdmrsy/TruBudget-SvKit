const core = require('@actions/core');
const github = require('@actions/github');
const child_process = require('child_process');

const SPAWN_PROCESS_BUFFER_SIZE = 10485760

const run = async function() {

  const projects = core.getInput('projects').split(',');
  if(!projects) {
    throw new Error('Project names are required');
  }
  for(const project of projects) {
    await runAudit(project);
  }
  return true;
}

async function runAudit(projectName) {
  console.log(`Auditing ${projectName}...`);
  if (!projectName) {
    throw new Error('A project name is required');
  }
  process.chdir(projectName);
  core.info(`Current working directory: ${process.cwd()}`);

  const auditCommand = "npm ci --no-audit --legacy-peer-deps && npm run audit -- --production";
  const result = child_process.spawnSync(auditCommand, {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE,
  });

  if(result.error) {
    
  }

  if(result.status === null) {
    core.setFailed("Audit process was killed");
  }

  if(result.stderr && result.stderr.length > 0) {
    core.setFailed(result.stderr);
  }

  const resultStripped = `\`\`\`\n${stripAnsi(this.stdout)}\n\`\`\``;

  if(result.status === 1) {
    // npm audit returns 1 if vulnerabilities are found 
    // get GitHub information
    const ctx = JSON.parse(core.getInput('github_context'))
    const token = core.getInput('github_token', {required: true});

    console.log(resultStripped);
    core.info(resultStripped);
    return false;

  } else {
    return true;
  }
}


function stripAnsi(string) {
  const pattern = [
    '[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)',
    '(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))'
    ].join('|');
	if (typeof string !== 'string') {
		throw new TypeError(`Expected a \`string\`, got \`${typeof string}\``);
	}

	return string.replace(new RegExp(pattern, 'g'), '');
}

run();