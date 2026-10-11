# Security policy

Balistid Blue is pre-alpha and not yet suitable for protecting a machine.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository.
Expect an answer within 7 days.

## Scope

In scope: code in this repository, its install path and its CI configuration.
Out of scope: the upstream tools Balistid Blue orchestrates (report those upstream), and findings that need
root on the protected host before Balistid Blue starts, unless Balistid Blue claims to detect exactly that.

## Supply chain

CI actions and dependencies are pinned by commit hash or content hash (ENGINEERING.md R14).
Release manifests will be signed with the maintainer's hardware key (R2); until then there are no
releases.
