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
    if(project === 'api') {
      await runAudit(project);
    }
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
  let result = child_process.spawnSync("npm", ["ci", "--no-audit", "--legacy-peer-deps"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });
  if(result.status === null) {
    core.setFailed("Audit process was killed");
  }
  if(result.stderr && result.stderr.length > 0) {
    core.setFailed(result.stderr);
  }

  result = child_process.spawnSync("npm", ["run", "audit", "--", "--production"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });
  
  if(result.status === null) {
    core.setFailed("Audit process was killed");
  }

  if(result.stderr && result.stderr.length > 0) {
    core.setFailed(result.stderr);
  }

  if(result.status === 0) {
    core.info("No vulnerabilities found");
  } else {
    core.info("Vulnerabilities found");
    let resultStripped = stripAnsi(result.stdout);
    resultStripped = resultStripped.replace(/[^a-zA-Z0-9\.\?\/\:\-\|\!\s]/gm, "");
    const dataString = resultStripped.split('npm audit security report')[1].trim();
    const data = [];
    let singleData = "";

    for(let i = 0; i < dataString.length; i++) {
      if(dataString.charAt(i).match(/\s/gm) == null) {
        singleData = singleData.concat(dataString.charAt(i));
      } else {
          if(i < dataString.length - 1 && dataString.charAt(i+1).match(/\s/gm) == null && dataString.charAt(i-1).match(/\s/gm) == null) {
            singleData = singleData.concat(dataString.charAt(i));
          } else {
            if(singleData.length > 0) {
              data.push(singleData);
              singleData = "";
            }
          
          }
      }

    }

    for(const dataItem of data) {
      core.info(dataItem);
    }
  }
  process.chdir('..');

  
/*
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
  }*/
}


function stripAnsi(string) {
  const pattern = [
    '[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)',
    '(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))',
    ].join('|');
	return string.replace(new RegExp(pattern, 'g'), '');
}

run();