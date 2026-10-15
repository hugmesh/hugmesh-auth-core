-- account schema for the auth-core R2DBC-H2 single-path SSO flow test (library has no
-- Liquibase changelog of its own — admin-bff owns the migrations). Mirrors the columns
-- AccountRow maps (changeset 004). Deliberately OMITS account.casdoor_sub (changeset 292,
-- owned by admin-bff, nullable): auth-core must keep working on a table that lacks it.
CREATE TABLE IF NOT EXISTS account (
    id                    VARCHAR(400) PRIMARY KEY,
    provider              VARCHAR(32) NOT NULL,
    handle                VARCHAR(320) NOT NULL,
    registration_complete BOOLEAN NOT NULL DEFAULT FALSE,
    roles                 VARCHAR(255) NOT NULL,
    updated_at            TIMESTAMP NOT NULL DEFAULT now()
);
