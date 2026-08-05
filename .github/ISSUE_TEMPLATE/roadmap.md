---
name: Hermternal roadmap operation
about: Plan one independently verifiable v0.0.1 operation
title: "[KEY] "
labels: []
assignees: []
---

<!-- Use Simplified Technical English. Keep one operation per issue. -->

## 1. One operation

<!-- State one observable result. Include the stable roadmap key. -->

## 2. Ownership and dependencies

- Owner: Unassigned until implementation starts.
- Assigned subagent: Unassigned until implementation starts.
- Reviewer:
- Child issues: None.

<!-- Every implementation subagent receives one issue as its work contract. It must complete this issue or create smaller child issues and delegate those units. Before finishing, it must leave a comment that states the current state, completed work, verification results, remaining limitations, and child issues. -->

### Hard blockers

-

### Soft sequence

-

## 3. Exact behavior

### Normal

-

### Loading or pending

-

### Empty

-

### Success

-

### Failure

-

### Interruption or cancellation

-

### Retry and recovery

-

## 4. Paper evidence

- Paper file: https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0
- Artboards:
- Static states:

<!-- Use N/A only for protocol, security, deployment, benchmark, or tooling work. Explain why. -->

## 5. Contract and tests

- Contract paths:
- Contract version or pinned Hermes SHA:
- Fixture IDs:
- Unit tests:
- Component or UI tests:
- Integration or deployment tests:
- Parity tests:
- Negative tests:
- Regression tests:

## 6. Accessibility

- Keyboard and focus:
- Semantic name:
- Screen reader or VoiceOver:
- Switch Control:
- Dynamic Type or browser zoom:
- Contrast:
- Reduced motion and reduced transparency:
- Touch target:

<!-- Mark an item N/A only with a reason. -->

## 7. Benchmark

- Deterministic fixture:
- Metric:
- Environment and device:
- Build mode:
- Repetitions and distribution:
- Trace artifact:
- Baseline or approved budget:

<!-- Before B-08, attach baseline evidence. Do not invent a final threshold. -->

## 8. Verification commands

```text
# Add exact commands and expected artifacts.
```

## 9. Evidence

- Pull request:
- Commit SHA:
- Paper review:
- Fixture diff:
- Test output:
- Accessibility result:
- Benchmark trace:
- Proxy or integration trace:
- Security and redaction review:

## 10. Definition of done

- [ ] The one operation is complete.
- [ ] Required normal and failure states pass.
- [ ] Regression tests exist and pass.
- [ ] Matching contracts, comments, and nearby documentation are updated.
- [ ] Paper matches the implementation, or an approved N/A reason is recorded.
- [ ] Accessibility checks pass where applicable.
- [ ] Measured performance evidence is attached.
- [ ] Security and privacy boundaries pass where applicable.
- [ ] `rtk diff` was reviewed.
- [ ] `code-review-graph update --brief` and change impact review are complete.
- [ ] The assigned subagent left a final issue comment with the current state, completed work, verification results, remaining limitations, and child issues.
- [ ] The focused commit and pull request are reviewed and integrated into `dev`.
