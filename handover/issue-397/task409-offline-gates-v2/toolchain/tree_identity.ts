import { treeIdentity } from '../../../../apps/web/benchmarks/production-build/run.ts';

const [browser, dependencies] = process.argv.slice(2);
if (!browser || !dependencies) throw new Error('two tree paths are required');

console.log(JSON.stringify({
  browser: await treeIdentity(browser),
  dependencies: await treeIdentity(dependencies, ['.vite', '.vite-temp'])
}));
