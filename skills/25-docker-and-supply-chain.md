# Docker and supply chain (the blast-radius and trust boundaries)

## What it is

Two related but distinct problems. **Container misconfiguration** widens the
blast radius of an application compromise: the app gets rooted, or escapes, or
reads the host's secrets. **Supply chain** moves the trust boundary outward: a
dependency, a base image, a CI step, or a GitHub Action is code you did not
audit, running with your permissions.

This skill covers both, because TriageKit's rules cover both, and because they
share one property: the finding is almost always a *configuration* line rather
than a dataflow, so reachability analysis does not apply. What applies instead is
honesty about what the configuration actually permits.

The trust boundary crossed in a container finding is between "the application
process" and "the host or the other tenants". The boundary crossed in a supply
chain finding is between "code the team reviewed" and "code a third party
reviewed".

## What TriageKit actually detects

Two rule lists in `src/triagekit/core/analyzers/repo_scan.py`, matched against
`Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`, `Makefile`, and CI
workflow files (line 186 enumerates the config-file set):

| Rule id | Severity | CWE | Pattern |
| --- | --- | --- | --- |
| `docker-user-root` | high | CWE-250 | a line matching `^\s*USER\s+root\s*$` |
| `docker-latest-tag` | medium | -- | any `:latest` |
| `docker-add-vs-copy` | low | -- | a line beginning `^\s*ADD ` |
| `docker-privileged` | critical | CWE-250 | `--privileged` |
| `docker-sensitive-port` | medium | -- | `EXPOSE` of 22, 23, 3306, 5432, 27017, 6379, 9200 |
| `ci-pipe-to-shell` | high | CWE-78 | `curl ... \| sh` or `wget ... \| (ba)sh` |
| `ci-overbroad-perms` | medium | -- | `permissions: write-all` or `contents: write` |

Plus, from the PR/heuristic layer: `dependency-change` (CWE-1104) and
`private-key-in-diff` (CWE-321).

**Known limitations, stated plainly:**

- **These are line patterns, not Docker semantics.** They do not parse a
  Dockerfile into stages, so a `USER root` in an early builder stage that is
  discarded in a multi-stage build is flagged. Read the stage structure before
  reporting.
- **No image scanning.** TriageKit queries OSV for *package manifests*; it does
  not pull or scan a base image's layers, and it does not have Trivy/Grype
  integration. A vulnerable base image is NOT detected.
- **No `docker-compose` semantic analysis.** `--privileged` in a compose file is
  matched as the same `--privileged` token as in a `docker run` command; whether
  the service is production-bound is a judgement.
- **No lockfile integrity checking.** No Sigstore/cosign, no SLSA attestation
  verification.
- **`docker-latest-tag` matches any `:latest`, including in a `FROM` of a
  discarded build stage** and in documentation.

## Detection (what to read by hand)

### Container blast radius

    FROM node:20                     # not node:20.11.1-alpine; a moving base
    USER root                        # docker-user-root: the app runs as root
    ADD https://... /app/            # docker-add-vs-copy: ADD fetches and unpacks
    COPY --chown=root:root . /app    # the files are root-owned in the image
    EXPOSE 5432                      # docker-sensitive-port: a DB port published
    docker run --privileged ...      # docker-privileged: full host device access
    --cap-add=SYS_ADMIN              # as dangerous as --privileged, not matched
    docker run -v /:/host ...        # the whole host filesystem, not matched
    --network host                   # shares the host network namespace, not matched
    -v /var/run/docker.sock:/...     # container escape, not matched

`--cap-add=SYS_ADMIN`, a `/:` bind mount, `--network host`, and a mounted
`docker.sock` are each as serious as `--privileged` and **none of them is
matched**. Grep for them.

### Supply chain

    # CI
    curl -fsSL https://get.example.com/install.sh | sh     # ci-pipe-to-shell
    wget -qO- https://x.example/install | bash             # ci-pipe-to-shell
    permissions: write-all                                 # ci-overbroad-perms
    # an action pinned to a mutable tag, not a commit SHA
    - uses: some-org/some-action@v4                       # not matched: pin to a SHA
    # a secret in an environment block
    env:
      API_KEY: "sk-live-..."                              # see skills/13-secrets-and-tokens.md
    # pull_request_target with a checkout of the PR head
    on: pull_request_target                               # not matched: privileged token, attacker code

`uses: ...@v4` (a mutable tag rather than a 40-hex commit SHA) is the single most
common supply-chain gap in GitHub Actions, and it is **not matched** by any rule
here. So is `pull_request_target` with a `checkout` of the PR head. Grep for both.

### Dependency manifests

`dependency-change` (CWE-1104) fires on a PR that changes a manifest or lockfile.
That is a prompt to read the diff, not a finding: a patch bump is routine, a
major bump is not. See `skills/18-dependency-cve.md` and
`skills/05-exploitdb-intel.md`.

## How it works (attack mechanics)

- **`USER root`.** Every vulnerability in the application is now a root
  vulnerability *inside* the container. With the default seccomp/AppArmor profile
  that is still contained, but it converts a file-read into an image-wide
  file-read and any container-escape primitive into a host-root primitive.
- **`--privileged`.** Disables seccomp, AppArmor, and device cgroup restrictions,
  and gives the container access to all host devices. That is a documented
  container-escape path, which is why the rule is `critical`.
- **`--cap-add=SYS_ADMIN`.** Grants nearly the same as `--privileged` -- mount,
  namespace manipulation -- while looking like a single, reasonable capability.
- **A mounted `docker.sock`.** Grants full control of the Docker daemon, which is
  root on the host. The standard escape.
- **`ci-pipe-to-shell`.** Executes a remote script with the CI job's permissions.
  Whoever controls the URL controls the script; whoever controls the script
  controls the job's token.
- **A mutable action tag.** `uses: org/action@v4` can be re-pointed by anyone
  with write access to that repository, at any time, without a visible change to
  your workflow. A commit SHA cannot.
- **`pull_request_target`.** Runs with a write token and, if the workflow checks
  out the PR head, executes attacker-controlled code with that token. This is the
  most severe CI pattern in existence and it is not matched.

## Is it actually exploitable?

1. **Is the Dockerfile multi-stage?** A `USER root` in a discarded builder stage
   does not ship. Read the last stage.
2. **Does the added capability actually get used?** `SYS_ADMIN` for a mount in an
   init job is a different finding from `SYS_ADMIN` on an internet-facing service.
3. **Is `--privileged` in production or in a local dev script?** A `Makefile`
   target that says `docker run --privileged` for a debugging session is a note.
4. **Does the `:latest` affect a shipped image or a discarded stage?**
5. **Does the `curl | sh` URL have a checksum or a pinned version?** A pinned,
   checksummed install is dramatically better; a bare `| sh` against a URL with
   no integrity check is the finding.
6. **Is the exposed port actually published, and to whom?** `EXPOSE` alone does
   not publish; `-p` or `ports:` does. A compose `ports:` binding to `127.0.0.1`
   is not internet-reachable.
7. **For a `dependency-change`, is it a major bump with a breaking change?** Read
   the release notes.

## False positives (do NOT report)

- **A `USER root` in a discarded multi-stage build stage.** Read the final stage.
- **A `:latest` in a `FROM` of a build stage that produces no shipped artifact.**
- **`ADD` of a local tarball or directory, not a URL.** `ADD ./src /app` is fine;
  `ADD https://... `/app` is not.
- **An `EXPOSE` with no `ports:`/`-p` publishing it.** The port is not reachable.
- **`--privileged` in a local development script, a Makefile debug target, or a
  test harness.** Note it with the context.
- **A `curl | sh` against a URL with a verified checksum on the next line.**
- **A patch-level dependency bump with a lockfile change only.**
- **A `USER` directive that is followed by a `chown` and a non-root `USER`.**
- **A GitHub Action pinned to a full commit SHA.** That is the fix, already
  applied.

The `docker-user-root` line-matching is the rule most likely to produce a false
positive, because multi-stage Dockerfiles are now the norm and the rule reads a
line rather than a stage.

## Severity

`--privileged` on a network-reachable service:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
```

`SC/SI/SA:H` because a successful escape compromises the host and every other
container on it -- a genuine subsequent system, not a repeat of the same impact.
A container running as root, without `--privileged`, is materially lower --
`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:H`, with `AT:P` because
escaping a default-profile container needs a further primitive and `AC:H` because
evading the default seccomp profile is exactly what `AC` measures. `ci-pipe-to-shell`
is `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` with `AT:P` because
the attacker must control the URL or its transport. Never hand-compute the number.

## Remediation

```dockerfile
# before                          # after
FROM node:latest                  FROM node:20.11.1-alpine@sha256:<digest>
USER root                         USER node                     # or a dedicated uid
ADD https://x.example/f /app/     COPY --from=builder /app /app  # build locally, copy
EXPOSE 5432                       EXPOSE 8080                   # an app port, not a DB port
```

```yaml
# before                              # after
- run: curl -sSL https://x/i.sh | sh  - run: |
                                            curl -sSL -o /tmp/i.sh https://x/i.sh
                                            echo "<sha256>  /tmp/i.sh" | sha256sum -c -
                                            sh /tmp/i.sh
permissions: write-all                permissions:
                                        contents: read
- uses: org/act@v4                    - uses: org/act@<40-hex-commit-sha>
```

```bash
# before                          # after
docker run --privileged app       docker run --cap-drop=ALL --security-opt=no-new-privileges app
docker run -v /:/host app         (delete the mount; bind only the path needed)
docker run -v /var/run/docker.sock:/var/run/docker.sock app   (delete; use a proxy)
```

The general rules: drop the root user, drop all capabilities and add back only
what is needed, pin base images by digest, publish only the application port,
bind mounts to specific paths, and pin CI actions to commit SHAs.

## Verify the fix

- `grep -n 'USER root\|--privileged\|--cap-add=SYS_ADMIN\|docker\.sock\|-v /:/host' Dockerfile docker-compose.yml` returns nothing in shipped stages.
- `docker run --rm <image> id -u` returns a non-zero uid.
- `grep -rn ':latest' Dockerfile* docker-compose*` returns nothing in a shipped
  `FROM`.
- `grep -rn '| sh\|| bash' .github/workflows/` returns nothing without an adjacent
  checksum check.
- `grep -rn 'uses: .*@' .github/workflows/` -- every entry matches
  `@[0-9a-f]{40}`, not a tag.
- `grep -rn 'pull_request_target' .github/workflows/` -- each occurrence either
  lacks a `checkout` of the PR head or is explicitly justified in a comment.
- A test that runs the container with `--security-opt=no-new-privileges` and
  confirms the app still starts, so the hardening is not silently breaking it.
