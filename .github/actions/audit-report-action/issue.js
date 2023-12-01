export async function createOrUpdateIssues(octokit, repo, vulnerabilityIdProjectMapping, activeVulnerabilities) {
  
  // Get all security labeled issues
  const { data: securityIssues} = await octokit.rest.issues.listForRepo(
    {
      ...repo,
      state: 'open',
      labels: ['security']
    }
  )

  const vulnerabilityIssues = securityIssues
    .filter(issue => issue.title.includes("Vulnerability Report:"));

    for (const vulnerability of activeVulnerabilities) {
      const vId = vulnerability.via[0].source;
      const vName = vulnerability.via[0].name;
      const vTitle = vulnerability.via[0].title;
      const vSeverity = vulnerability.via[0].severity;
      const vUrl = vulnerability.via[0].url;
      const vEffects = vulnerability.effects;

      const issueTitle = `Vulnerability Report: ${vId} - ${vName}`;
      const issue = vulnerabilityIssues.filter(issue => issue.title === issueTitle)[0];

      if(issue) {
          //update issue
        await updateExistingIssue(octokit.rest.issues.update, repo, issue, affectedProjects);
      } else {
        const affectedProjects = vulnerabilityIdProjectMapping.get(vId);
        await createNewIssue(octokit.rest.issues.create, repo, vId, vName, vTitle, vSeverity, vUrl, vEffects, affectedProjects, issueTitle);
      }
    }

  // Close issues referencing fixed vulnerabilities if not closed manually.
  await closeOldIssues(octokit.rest.issues.update, repo, vulnerabilityIssues, vulnerabilityIdProjectMapping);
}

async function updateExistingIssue(updateFunc, repo, issue, affectedProjects) {
  const issueNumber = issue.number;
  const issueBody = issue.body.replace(/[0-9]{1,2}\/[0-9]{1,2}\/[0-9]{4}/gm, "abc");
  await updateFunc({
    ...repo,
    issue_number: issueNumber,
    body: issueBody
  });
}

async function createNewIssue(createFunc, repo, vId, vName, vTitle, vSeverity, vUrl, vEffects, affectedProjects, issueTitle) {
  let newIssueBody = `<h2 id="last-checked-date-">Last checked date:</h2>
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
          <td>[${vUrl}](${vUrl})</td>
          <td>${vEffects.toString()}</td>
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
    ...repo,
    title: issueTitle,
    body: newIssueBody,
    labels: ["security"]
  });
}

async function closeOldIssues(updateFunc, repo, vulnerabilityIssues, vulnerabilityIdProjectMapping) {
  for(const vulnerabilityIssue of vulnerabilityIssues) {
    const issueVId = Number(vulnerabilityIssue.title.split(": ")[1].split(" - ")[0]);
    if(!vulnerabilityIdProjectMapping.has(issueVId)){
      // There is an open issue referencing inactive vulnerability
      await updateFunc({
        ...repo,
        issue_number: vulnerabilityIssue.number,
        state: 'closed'
      })
    }
  }
}