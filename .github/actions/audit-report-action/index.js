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

  let result = child_process.spawnSync("npm", ["ci", "--no-audit", "--legacy-peer-deps"], {
    encoding: 'utf-8',
    maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
  });

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
    core.info(result.output[2].split("Node security advisories: ")[1]);
    core.info(result.output[2].split("Node security advisories: ")[1].split(",")[1]);
    let resultStripped = stripAnsi(result.stdout);
    resultStripped = resultStripped.replace(/[^a-zA-Z0-9\.\?\/\:\-\|\!\s]/gm, "");
    const dataString = resultStripped.split('npm audit security report')[1].trim();
    core.info(dataString);
    const data = [];
    let singleData = "";

    for(let i = 0; i < dataString.length; i++) {
      if(dataString.charAt(i).match(/\s/gm) == null) {
        singleData = singleData.concat(dataString.charAt(i));
        if(i === dataString.length - 1) {
          data.push(singleData);
        }
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
    const id = data[7];
    const module = data[8];
    const description = data[9];
    const paths = data[10];
    const severity = data[11];
    const url = data[12];
    const excluded = data[13];

    process.chdir('..');
  }
}

  
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



function stripAnsi(string) {
  const pattern = [
    '[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)',
    '(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))',
    ].join('|');
	return string.replace(new RegExp(pattern, 'g'), '');
}

run();