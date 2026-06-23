-- MFA-table schema for the auth-core R2DBC data-slice tests. auth-core is a LIBRARY with
-- no Liquibase changelog of its own — prod DDL for these tables lives in admin-bff
-- changesets 151 (mfa_factor / mfa_recovery_code / webauthn_credential) and 152
-- (webauthn_challenge). This mirror reproduces the production columns + the DB-GENERATED
-- UUID PK: each id is varchar(36) with a DEFAULT (gen_random_uuid())::text so an INSERT
-- that OMITS id (the release-2.3.0 INSERT ... RETURNING id idiom) gets a database-minted id.
--
-- These tests run on REAL Postgres (commons PostgresTestSupport / Testcontainers), NOT H2:
-- gen_random_uuid() and INSERT ... RETURNING are Postgres features H2 does not honour. The
-- pgcrypto extension provides gen_random_uuid() on the Postgres versions in scope (it is
-- also a Postgres-13+ core builtin, but the CREATE EXTENSION keeps older images working).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- mfa_factor (admin-bff changeset 151): an enrolled TOTP or WebAuthn second factor.
CREATE TABLE IF NOT EXISTS mfa_factor (
    id              VARCHAR(36) PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    owner_subject   VARCHAR(400) NOT NULL,
    type            VARCHAR(32)  NOT NULL,
    totp_secret_enc TEXT,
    last_counter    BIGINT,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- mfa_recovery_code (admin-bff changeset 151): a single recovery code, stored as ONLY a
-- salted hash, single-use via the used flag.
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
    id            VARCHAR(36) PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    owner_subject VARCHAR(400) NOT NULL,
    code_hash     TEXT NOT NULL,
    used          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- webauthn_credential (admin-bff changeset 151): a registered WebAuthn credential; the
-- credential_id is UNIQUE (no dup registration) and sign_count advances monotonically.
CREATE TABLE IF NOT EXISTS webauthn_credential (
    id              VARCHAR(36) PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    owner_subject   VARCHAR(400) NOT NULL,
    credential_id   TEXT NOT NULL UNIQUE,
    public_key_cose TEXT,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- webauthn_challenge (admin-bff changeset 152): a single PENDING WebAuthn challenge bound
-- to (owner_subject, ceremony_type), ~5m TTL via expires_at, single-use via used.
CREATE TABLE IF NOT EXISTS webauthn_challenge (
    id            VARCHAR(36) PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    owner_subject VARCHAR(400) NOT NULL,
    challenge     TEXT NOT NULL,
    ceremony_type VARCHAR(32) NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
