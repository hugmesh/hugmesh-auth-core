-- allowlist schema for the auth-core R2DBC-H2 data-slice tests (library has no Liquibase
-- changelog of its own — admin-bff owns the migrations). Mirrors the production table:
-- changeset 003 (provider/handle/created_at, PK provider+handle) as widened by 220
-- (domain discriminator, PK provider+handle+domain). H2 runs in PostgreSQL-compat mode so
-- the derived-finder SQL exercises here as on Postgres.
CREATE TABLE IF NOT EXISTS allowlist (
    provider   VARCHAR(32) NOT NULL,
    handle     VARCHAR(320) NOT NULL,
    domain     VARCHAR(64) NOT NULL DEFAULT 'default',
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, handle, domain)
);
