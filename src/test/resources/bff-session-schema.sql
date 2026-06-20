-- bff_session schema for the auth-core R2DBC-H2 data-slice tests (library has no
-- Liquibase changelog of its own — admin-bff owns the migrations). Mirrors the
-- production table: changeset 006 (token/account_id/created_at/expires_at) + 150
-- (mfa_satisfied/mfa_satisfied_at/amr) + the band-180 OIDC token-custody columns
-- (access_token_enc/refresh_token_enc/access_token_expires_at/custody_updated_at).
-- H2 runs in PostgreSQL-compat mode so the same DDL + partial-update SQL exercise
-- here as on Postgres.
CREATE TABLE IF NOT EXISTS bff_session (
    token                   VARCHAR(64) PRIMARY KEY,
    account_id              VARCHAR(400) NOT NULL,
    created_at              TIMESTAMP NOT NULL DEFAULT now(),
    expires_at              TIMESTAMP NOT NULL,
    mfa_satisfied           BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_satisfied_at        TIMESTAMP,
    amr                     CLOB,
    access_token_enc        CLOB,
    refresh_token_enc       CLOB,
    access_token_expires_at TIMESTAMP,
    custody_updated_at      TIMESTAMP
);
