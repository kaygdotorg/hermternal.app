export const LIVE_PROOF_PHASE_ANNOTATION = 'hermternal.live-proof.phase';
export const LIVE_PROOF_DELIVERY_ANNOTATION = 'hermternal.live-proof.delivery';

export const LIVE_PROOF_PHASES = Object.freeze([
  'not-started',
  'authenticated',
  'ready-no-submit',
  'submitted',
  'completed',
  'history-reconciled',
  'reconciled',
  'uncertain'
]);

export const LIVE_PROOF_DELIVERY_STATUSES = Object.freeze([
  'not-submitted',
  'submitted',
  'completed',
  'reconciled',
  'uncertain'
]);

export const LIVE_PROOF_INITIAL_STATUS = Object.freeze({
  phase: 'not-started',
  delivery: 'not-submitted'
});

const LIVE_PROOF_STATUS_ANNOTATION_TYPES = Object.freeze([
  LIVE_PROOF_PHASE_ANNOTATION,
  LIVE_PROOF_DELIVERY_ANNOTATION
]);
const ANNOTATION_KEYS = Object.freeze(['type', 'description']);

/**
 * Keep the worker-to-reporter channel deliberately narrower than Playwright's
 * general annotation API. Dynamic annotations carry only the last reviewed
 * phase and delivery state; they must never become a diagnostic side channel.
 *
 * @param {unknown} testInfo
 * @param {{ phase: string, delivery: string }} status
 */
export function setLiveProofStatus(testInfo, status) {
  if (testInfo === null || typeof testInfo !== 'object') {
    throw new Error('live proof status target is not available');
  }
  const target = /** @type {{ annotations?: unknown }} */ (testInfo);
  if (!Array.isArray(target.annotations)) {
    throw new Error('live proof status target is not available');
  }
  const next = assertLiveProofStatus(status);
  const annotations = /** @type {Array<Record<string, unknown>>} */ (target.annotations);
  const current = readLiveProofStatus(annotations);
  for (let index = annotations.length - 1; index >= 0; index -= 1) {
    const type = annotations[index]?.type;
    if (typeof type === 'string' && LIVE_PROOF_STATUS_ANNOTATION_TYPES.includes(type)) annotations.splice(index, 1);
  }
  annotations.push(
    { type: LIVE_PROOF_PHASE_ANNOTATION, description: next.phase },
    { type: LIVE_PROOF_DELIVERY_ANNOTATION, description: next.delivery }
  );
  return Object.freeze({ ...current, ...next });
}

/**
 * Read only the two exact annotations owned by this channel. Untrusted or
 * duplicated values fail closed instead of being rendered by a reporter.
 *
 * @param {unknown} annotations
 */
export function readLiveProofStatus(annotations) {
  if (!Array.isArray(annotations)) throw new Error('live proof status annotations are unavailable');
  const owned = annotations.filter((annotation) =>
    annotation !== null &&
    typeof annotation === 'object' &&
    typeof annotation.type === 'string' &&
    LIVE_PROOF_STATUS_ANNOTATION_TYPES.includes(annotation.type)
  );
  const phaseAnnotation = owned.filter((annotation) => annotation.type === LIVE_PROOF_PHASE_ANNOTATION);
  const deliveryAnnotation = owned.filter((annotation) => annotation.type === LIVE_PROOF_DELIVERY_ANNOTATION);
  if (phaseAnnotation.length === 0 && deliveryAnnotation.length === 0) {
    return LIVE_PROOF_INITIAL_STATUS;
  }
  if (phaseAnnotation.length !== 1 || deliveryAnnotation.length !== 1) {
    throw new Error('live proof status annotations are duplicated');
  }
  assertExactAnnotation(phaseAnnotation[0]);
  assertExactAnnotation(deliveryAnnotation[0]);
  return assertLiveProofStatus({
    phase: phaseAnnotation[0].description,
    delivery: deliveryAnnotation[0].description
  });
}

/**
 * @param {{ phase: string, delivery: string }} status
 */
export function assertLiveProofStatus(status) {
  if (
    status === null ||
    typeof status !== 'object' ||
    Array.isArray(status) ||
    Object.keys(status).length !== 2 ||
    typeof status.phase !== 'string' ||
    typeof status.delivery !== 'string' ||
    !LIVE_PROOF_PHASES.includes(status.phase) ||
    !LIVE_PROOF_DELIVERY_STATUSES.includes(status.delivery)
  ) {
    throw new Error('live proof status is not allowlisted');
  }
  return Object.freeze({ phase: status.phase, delivery: status.delivery });
}

/**
 * Format only the fixed failure projection. Do not add titles, locations,
 * errors, URLs, identifiers, or other free-form values to this line.
 *
 * @param {{ phase: string, delivery: string }} status
 */
export function formatLiveProofFailureStatus(status) {
  const safe = assertLiveProofStatus(status);
  return `live proof failure\tphase=${safe.phase}\tdelivery=${safe.delivery}`;
}

/** @param {Record<string, unknown>} annotation */
function assertExactAnnotation(annotation) {
  const keys = Object.keys(annotation).sort();
  if (keys.length !== ANNOTATION_KEYS.length || keys[0] !== 'description' || keys[1] !== 'type') {
    throw new Error('live proof status annotation shape is not approved');
  }
  if (typeof annotation.type !== 'string' || typeof annotation.description !== 'string') {
    throw new Error('live proof status annotation value is not approved');
  }
}
