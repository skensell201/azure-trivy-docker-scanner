#!/usr/bin/env node
// Assembles the TrivyScan folder that tfx packages: compiled js, task.json and runtime deps.
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const out = path.join(root, 'TrivyScan');

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

// Preserve the build/task + build/shared sibling layout: the compiled task requires
// '../shared/...', which only resolves correctly when that relative relationship survives
// the copy. Flattening build/task straight into the TrivyScan root breaks it, because then
// '../shared/x' resolves one directory above TrivyScan instead of into it (verified by
// running the assembled entry point - see npm run build:task). So compiled task code goes
// into TrivyScan/task/ and shared code into TrivyScan/shared/, matching build/'s own layout.
//
// task.json itself still has to live at the TrivyScan root: that is where tfx and the Azure
// DevOps server look for it via the task contribution. Its source (src/task/task.json)
// declares "target": "index.js" because that is the right path when hand-testing the task
// directly out of build/task. Here the entry point instead lands at TrivyScan/task/index.js,
// so the target is rewritten to "task/index.js" on the copy that ships in the package,
// without touching the source file.
fs.cpSync(path.join(root, 'build', 'task'), path.join(out, 'task'), { recursive: true });
fs.cpSync(path.join(root, 'build', 'shared'), path.join(out, 'shared'), { recursive: true });

const taskJson = JSON.parse(fs.readFileSync(path.join(root, 'src', 'task', 'task.json'), 'utf8'));
for (const executionHandler of Object.values(taskJson.execution)) {
  executionHandler.target = `task/${executionHandler.target}`;
}
fs.writeFileSync(path.join(out, 'task.json'), JSON.stringify(taskJson, null, 2) + '\n');

// A pipeline task carries its own icon: the task picker looks for a 32x32 icon.png next to
// task.json inside the task folder. images/icon.png is the extension's icon and is only used
// in the installed-extensions list, so without this copy the task shows a generic placeholder.
fs.copyFileSync(path.join(root, 'src', 'task', 'icon.png'), path.join(out, 'icon.png'));

const rootPackage = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
fs.writeFileSync(
  path.join(out, 'package.json'),
  JSON.stringify(
    {
      name: 'trivy-scan-task',
      version: rootPackage.version,
      main: 'index.js',
      dependencies: rootPackage.dependencies,
    },
    null,
    2,
  ),
);

execSync('npm install --omit=dev --no-package-lock', { cwd: out, stdio: 'inherit' });
console.log(`Task assembled in ${out}`);
