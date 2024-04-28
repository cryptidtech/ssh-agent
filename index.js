const core = require('@actions/core');
const child_process = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const { homePath, sshAgentCmdDefault, sshAddCmdDefault, sshCmdDefault, gitCmdDefault } = require('./paths.js');

try {
    const privateKey = core.getInput('ssh-private-key');
    const logPublicKey = core.getBooleanInput('log-public-key', {default: true});

    const sshAgentCmdInput = core.getInput('ssh-agent-cmd');
    const sshAddCmdInput = core.getInput('ssh-add-cmd');
    const sshCmdInput = core.getInput('ssh-cmd');
    const gitCmdInput = core.getInput('git-cmd');

    const sshAgentCmd = sshAgentCmdInput ? sshAgentCmdInput : sshAgentCmdDefault;
    const sshAddCmd = sshAddCmdInput ? sshAddCmdInput : sshAddCmdDefault;
    const sshCmd = sshCmdInput ? sshCmdInput : sshCmdDefault;
    const gitCmd = gitCmdInput ? gitCmdInput : gitCmdDefault;

    if (!privateKey) {
        core.setFailed("The ssh-private-key argument is empty. Maybe the secret has not been configured, or you are using a wrong secret name in your workflow file.");

        return;
    }

    const homeSsh = homePath + '/.ssh';
    fs.mkdirSync(homeSsh, { recursive: true });

    console.log("Starting ssh-agent");

    const authSock = core.getInput('ssh-auth-sock');
    const sshAgentArgs = (authSock && authSock.length > 0) ? ['-a', authSock] : [];

    // Extract auth socket path and agent pid and set them as job variables
    child_process.execFileSync(sshAgentCmd, sshAgentArgs).toString().split("\n").forEach(function(line) {
        const matches = /^(SSH_AUTH_SOCK|SSH_AGENT_PID)=(.*); export \1/.exec(line);

        if (matches && matches.length > 0) {
            // This will also set process.env accordingly, so changes take effect for this script
            core.exportVariable(matches[1], matches[2])
            console.log(`${matches[1]}=${matches[2]}`);
        }
    });

    console.log("Adding private key(s) to agent");

    privateKey.split(/(?=-----BEGIN)/).forEach(function(key) {
        child_process.execFileSync(sshAddCmd, ['-'], { input: key.trim() + "\n" });
    });

    console.log("Key(s) added:");

    child_process.execFileSync(sshAddCmd, ['-l'], { stdio: 'inherit' });

    console.log('Configuring deployment key(s)');

    child_process.execFileSync(sshAddCmd, ['-L']).toString().trim().split(/\r?\n/).forEach(function(key) {
        const parts = key.match(/\bgithub\.com[:/]([_.a-z0-9-]+\/[_.a-z0-9-]+)/i);

        if (!parts) {
            if (logPublicKey) {
              console.log(`Comment for (public) key '${key}' does not match GitHub URL pattern. Not treating it as a GitHub deploy key.`);
            }
            return;
        }

        const sha256 = crypto.createHash('sha256').update(key).digest('hex');
        const ownerAndRepoGit = parts[1];
        const ownerAndRepo = parts[1].replace(/\.git$/, '');

        console.log(`ownerAndRepo: ${ownerAndRepo}`);

        console.log(`create: ${homeSsh}/key-${sha256}\n${key}\n`);
        fs.writeFileSync(`${homeSsh}/key-${sha256}`, key + "\n", { mode: '600' });


        //console.log(`exec: ${gitCmd} config --global --replace-all url."git@key-${sha256}.github.com:${ownerAndRepoGit}".insteadOf "https://github.com/${ownerAndRepoGit}"`);
        //child_process.execSync(`${gitCmd} config --global --replace-all url."git@key-${sha256}.github.com:${ownerAndRepoGit}".insteadOf "https://github.com/${ownerAndRepoGit}"`);

        //console.log(`exec: ${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepoGit}".insteadOf "git@github.com:${ownerAndRepoGit}"`);
        //child_process.execSync(`${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepoGit}".insteadOf "git@github.com:${ownerAndRepoGit}"`);

        console.log(`exec: ${gitCmd} config --global --add url."ssh://git@key-${sha256}.github.com/${ownerAndRepoGit}".insteadOf "ssh://git@github.com/${ownerAndRepoGit}"`);
        child_process.execSync(`${gitCmd} config --global --add url."ssh://git@key-${sha256}.github.com/${ownerAndRepo}".insteadOf "ssh://git@github.com/${ownerAndRepoGit}"`);

        const result = child_process.execSync(`${gitCmd} config --list`);
        console.log(`gitconfig:\n${result}\n`);

        const sshConfig = `\nHost key-${sha256}.github.com\n`
                              + `    HostName github.com\n`
                              + `    IdentityFile ${homeSsh}/key-${sha256}\n`
                              + `    IdentitiesOnly yes\n`;

        console.log(`append to ${homeSsh}/config:\n${sshConfig}`);
        fs.appendFileSync(`${homeSsh}/config`, sshConfig);

        console.log(`Added deploy-key mapping: Use identity '${homeSsh}/key-${sha256}' for GitHub repository ${ownerAndRepo}`);

        console.log(`exec: ${sshCmd} git@github.com`);
        const ssh_github_output_1 = child_process.execFileSync(sshCmd, [`git@github.com`], { stdio: 'inherit' }).toString();
        console.log(`ssh to git@github.com:\n${ssh_github_output_1}`);

        console.log(`exec: ${sshCmd} git@key-${sha256}.github.com`);
        const ssh_github_output_2 = child_process.execFileSync(sshCmd, [`git@key-${sha256}.github.com`], { stdio: 'inherit' }).toString();
        console.log(`ssh to git@key-${sha256}.github.com:\n${ssh_github_output_2}`);
    });

} catch (error) {

    if (error.code == 'ENOENT') {
        console.log(`The '${error.path}' executable could not be found. Please make sure it is on your PATH and/or the necessary packages are installed.`);
        console.log(`PATH is set to: ${process.env.PATH}`);
    }

    core.setFailed(error.message);
}
