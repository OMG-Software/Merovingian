# Every workflow installs Python tools from hash-locked wheels

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-31

Technical Story: 0.12.66; SonarQube Cloud findings githubactions:S8541 and githubactions:S8544.

## Context and Problem Statement

ADR-0250 locked the SonarQube Cloud job's build tools: it installs Meson and Ninja with
`pip install --require-hashes --only-binary :all: --requirement requirements-build.txt`,
because that job holds `SONAR_TOKEN`. Every other workflow that builds the server (`ci.yml`,
`sanitizers.yml`, `fuzz.yml`, `release.yml`, `postgres-integration.yml`, `coverage.yml`,
`codeql.yml`, `static-analysis.yml`) still ran `pip install --upgrade pip` and
`pip install --upgrade meson ninja`: whatever PyPI served that day, sdists included, whose setup
scripts run during installation. `pages.yml` installed hash-locked requirements but still
accepted sdists.

Those jobs are not harmless. `release.yml` builds the packages it signs and publishes; a
compromised Meson or Ninja release would be built into them. `coverage.yml` holds
`CODECOV_TOKEN`, and `pages.yml` deploys the documentation site. Should only jobs holding a
secret be locked, or every workflow?

## Considered Options

* Lock every workflow's `pip install` to hash-locked wheels from a requirements file
* Lock only the jobs that hold a secret or publish something, as ADR-0250 did
* Pin versions (`meson==1.12.1`) without hashes

## Decision Outcome

Chosen option: lock every workflow. Each `pip install` in `.github/workflows/` reads a
requirements file with `--require-hashes --only-binary :all:`, names nothing else, and does not
upgrade pip. `requirements-build.txt` serves the build jobs and `requirements-docs.txt` the
documentation site; both are compiled with `--only-binary :all:`, so a regenerated lock never
takes an sdist the install would refuse. `tests/tooling/test_workflow_pip_locking.py`
(`workflow-pip-locking-tooling`) enforces this for every workflow, including new ones.

### Positive Consequences

* A build job runs the Meson and Ninja that were reviewed, the same ones in every job, and no
  package's setup script.
* A new workflow cannot quietly reintroduce an unlocked install; the tooling test fails.

### Negative Consequences

* Moving to a newer Meson or Ninja is a deliberate change: edit `requirements-build.in` and
  regenerate `requirements-build.txt` with the command in its header.
* Jobs use the runner's own pip, no longer the newest one.

## Pros and Cons of the Options

### Lock only the jobs that hold a secret or publish something

* Good, because it is what ADR-0250 already did.
* Bad, because which job holds a secret changes over time, and the release job, which publishes,
  was missed: the rule has to be remembered per job, and it was not.
* Bad, because jobs then build with different Meson releases, so a failure in one may not
  reproduce in another.

### Pin versions without hashes

* Good, because it is a one-line change per job.
* Bad, because a version number does not stop a replaced or yanked-and-reuploaded file, and
  without `--only-binary` an sdist still runs its setup script.

## Links

* Refines [ADR-0250](0250-sonarqube-cloud-analysis-runs-in-ci-against-the-build-s-compilation-database.md)
* Related to [ADR-0266](0266-pin-third-party-github-actions-to-a-full-commit-sha.md)
