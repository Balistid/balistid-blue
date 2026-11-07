# 0053 — Sign install manifests with a FIDO2 SSH key

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-03; the key type is the maintainer's choice)
- Agent: claude/opus-5.5
- Decides R2's key for issue #196 and T9.

## Context

R2 counts a manifest of approved digests only when it is signed with the maintainer's hardware key, and T9 notes
that no such key exists, so root installs by typing CI's sha256 by hand (the exception #196 retires). Every
supported host (Arch, Ubuntu LTS) ships OpenSSH, whose `ssh-keygen -Y sign` and `-Y verify` sign files with a
namespace and check them against an allowed-signers file, and whose `ed25519-sk` keys live on a FIDO2 token.

## Decision

1. The maintainer's signing key is an `ed25519-sk` key on a FIDO2 token, made with `ssh-keygen -t ed25519-sk -O
   verify-required`: each signature needs the token, a touch and its PIN. The key handle file is useless without
   the token; no agent, CI job or host ever holds a signing key.
2. A manifest is the list of path and sha256 that CI prints for a release. The maintainer signs it on his own
   machine with `ssh-keygen -Y sign -f <key> -n install@balistid.dev <manifest>`, which writes `<manifest>.sig`.
3. `balistid-install` changes nothing before `ssh-keygen -Y verify -f /etc/balistid/allowed_signers -I
   maintainer@balistid.dev -n install@balistid.dev -s <manifest>.sig < <manifest>` exits 0, then installs only the
   files the manifest lists, each checked against its sha256. It refuses an unsigned or altered manifest, another
   namespace and another signer, each with a test (#196's done criterion).
4. `/etc/balistid/allowed_signers` is root-owned, 0644, one line with `namespaces="install@balistid.dev"`. The first
   install takes it from the release with the key's fingerprint, which the install documentation tells the user to
   compare with the one published on balistid.dev and in `README.md`: trust on first use, stated.
5. A lost or replaced key: a new `allowed_signers` installed by hand as in point 4, announced where the fingerprint
   is published. Rotation signed by the old key comes when a second maintainer exists.

## Alternatives considered

- An OpenPGP card and `gpg --verify`: GnuPG on every host only to verify, harder for the first users (K1).
- minisign or signify: no hardware key, so R2 would stay unmet.
- Sigstore keyless signing: the identity is CI's or an OIDC account, not a key the maintainer holds offline.

## Consequences

- The maintainer needs a FIDO2 token with resident or non-resident ed25519-sk support before #196 can be tested.
- T9's "no R2 hardware key yet" closes when #196 lands; "sha256 proves CI provenance, not review" stays.
- Trust on first use: a user who skips the fingerprint check trusts whoever served the release.
- Revert: a pull request removing this file; #196 then has no key decision.
