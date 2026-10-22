# Security Policy — hugmesh-auth-core

This library holds the account, session, MFA (TOTP and WebAuthn) and Casdoor-admin code
that the HugMesh user and admin BFFs share. A flaw here can let someone sign in as another
person, keep a session after it should have ended, or skip MFA. Please report it privately.

## How to report

- Use GitHub's private vulnerability reporting for this repository: open the **Security**
  tab and choose **Report a vulnerability**. Only you and the maintainers see the report.
- Do **not** open a public issue, pull request or discussion that describes the problem.
- If you cannot find the **Report a vulnerability** button, open a public issue titled
  "Security contact request" that says only that you have something to report, with no
  details. A maintainer will reply with a private way to send it.

Helpful things to include: the affected class or endpoint, the commit or version you
tested, the steps to reproduce, and what an attacker gains.

## What happens next

We will acknowledge your report as quickly as we can, agree a fix and a disclosure date
with you, and credit you in the advisory unless you ask us not to. Keep the details
private until the fix has shipped.

## Which versions get fixes

Fixes land on `main` and ship in the next release of `net.hugmesh:hugmesh-auth-core`.
Older versions do not get backported fixes, so upgrade to the newest release.

## In scope

- Session handling: the opaque `bff_` session, its introspection and exchange, and how
  roles and authorities are built from it.
- MFA: TOTP and WebAuthn verification and step-up.
- The AES-256-GCM crypto helpers and how keys and secrets are loaded.
- The Casdoor-admin client and the account, allowlist and suspension stores.

A problem in a service that uses this library (for example a BFF or the gateway) belongs
in that service's repository, but if you are not sure where it lives, report it here.
