const rendererModuleKey = 'src/lib/terminal/renderer.ts';

function emittedOutputs(entry) {
  return [entry.file, ...(entry.css ?? []), ...(entry.assets ?? [])].filter(Boolean);
}

function collectRendererOwnedClosure(rootKey, manifestEntries) {
  const root = manifestEntries.get(rootKey);
  if (!root) throw new Error(`Client manifest contains an unresolved terminal dependency: ${rootKey}`);

  // The renderer entry itself and every module reached once its lazy boundary
  // opens are terminal-owned. Root static imports are deliberately excluded:
  // Vite may factor general runtime helpers into both graphs before the lazy
  // boundary. Every dynamic descendant, however, is followed transitively.
  const pending = [rootKey, ...(root.dynamicImports ?? [])];
  const closure = new Set();
  while (pending.length > 0) {
    const key = pending.pop();
    if (closure.has(key)) continue;
    const entry = manifestEntries.get(key);
    if (!entry) throw new Error(`Client manifest contains an unresolved terminal dependency: ${key}`);
    closure.add(key);
    if (key === rootKey) continue;
    for (const dependency of [...(entry.imports ?? []), ...(entry.dynamicImports ?? [])]) {
      pending.push(dependency);
    }
  }
  return closure;
}

/**
 * Reject terminal-owned emitted files in the initial live route closure.
 *
 * Vite can rename or attach CSS/WASM to arbitrary importers. Derive ownership
 * from the renderer's manifest dependency graph rather than emitted filenames,
 * then compare its files/CSS/assets with the route's static manifest closure.
 */
export function assertTerminalLazyBoundary(staticClosure, manifestEntries) {
  const staticOutputs = new Set();
  for (const entryKey of staticClosure) {
    const entry = manifestEntries.get(entryKey);
    if (!entry) throw new Error(`Client manifest contains an unresolved static import: ${entryKey}`);
    for (const output of emittedOutputs(entry)) staticOutputs.add(output);
  }

  const terminalClosure = collectRendererOwnedClosure(rendererModuleKey, manifestEntries);
  // Module keys identify emitted JavaScript even when a neutral filename conceals
  // terminal provenance. The renderer root and every lazy descendant must stay
  // out of the initial route closure; Vite must split a would-be shared module.
  for (const key of terminalClosure) {
    if (staticClosure.has(key)) {
      throw new Error(`Terminal renderer dependency entered the initial route closure: ${key}`);
    }
  }
  const terminalOutputs = new Set();
  for (const entryKey of terminalClosure) {
    const entry = manifestEntries.get(entryKey);
    for (const output of emittedOutputs(entry)) terminalOutputs.add(output);
  }

  for (const output of terminalOutputs) {
    if (staticOutputs.has(output)) {
      throw new Error(`Terminal renderer output entered the initial route closure: ${output}`);
    }
  }

  return staticOutputs;
}
