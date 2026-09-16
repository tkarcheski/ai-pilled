# User-approved feature list

Extracted verbatim from initial README. Feature intent is authoritative; original implementation and provider claims are not.

## Core Features

### 1. **Security Auditor Agent**
Runs on every file edit. Checks for:
- Hardcoded secrets (AWS keys, tokens)
- Environment variable leaks
- Unsafe crypto/parsing patterns

### 2. **Code Reviewer Agent**
Runs on every `git commit`. Checks:
- Commit message clarity (conventional commits)
- Changes align with message
- Obvious bugs or logic errors
- Dead code or unused imports

### 3. **Pre-Push Validator Agent**
Runs on every `git push`. Validates:
- Pushing to correct branch
- No secrets in commits
- Follows project conventions
- Tests passed (if configured)

### 4. **Dependency Auditor Agent**
Runs on `npm install`, `yarn add`, etc. Audits:
- Known vulnerabilities (CVE)
- Outdated or security-critical updates
- Conflicting versions
- License compliance

### 5. **Batch Summarizer Agent**
Runs after every tool chain. Provides:
- One-sentence summary (what just happened)
- Any errors or warnings
- Next logical step
- Blocker status (proceed or wait)


## Default Automations

### Tier 1: Merge Requests 
1. Dead code detector
2. Type safety verifier
3. Dependency health checker
4. Commit message validator
5. Branch protector

### Tier 2: Nightly/Release
6. Test coverage auditor
7. Performance regression detector
8. Bundle size watcher
9. Changelog auto-generator
10. README updater

### Tier 3: Weekly/Planning
11. Full audit workflow (parallel agents)
12. PR-ready checker
13. Release flow automation
14. Refactor flow (simplify → fix → test)

### Tier 4: Instant Integrations
15. Slack notifications
16. Linear ticket creation
17. GitHub auto-comments
18. Email digests
19. Metrics dashboards

### Roadmap Experimental Features
20. Semantic release (auto-version)
21. Trunk-based dev (auto-merge)
22. AI bug bounty (find issues)
23. Nightly refactoring
24. Self-healing (auto-revert breaks)

