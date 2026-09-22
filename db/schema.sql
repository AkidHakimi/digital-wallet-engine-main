-- Digital Wallet — MySQL schema
-- Run once: mysql -u root -p digital_wallet < db/schema.sql

-- ── Legacy single-party tables (kept for migration read) ─────────────────

CREATE TABLE IF NOT EXISTS credentials (
  credential_id    VARCHAR(255) NOT NULL,
  credential       JSON         NOT NULL,
  issuer_did       VARCHAR(255) NOT NULL,
  subject_did      VARCHAR(255) NOT NULL,
  issuance_date    DATETIME     NOT NULL,
  expiration_date  DATETIME,
  stored_at        TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  -- multi-tenant + multi-key additions
  tenant_id        BIGINT,
  signing_key_did  VARCHAR(512),
  status_list_id   BIGINT,
  status_list_index INT,
  schema_id        VARCHAR(512),
  credential_format ENUM('vc-ld','sd-jwt') NOT NULL DEFAULT 'vc-ld',
  sd_jwt           MEDIUMTEXT,
  PRIMARY KEY (credential_id),
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_signing_key (signing_key_did),
  INDEX idx_status_list (status_list_id, status_list_index)
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge   CHAR(36)     NOT NULL,
  domain      VARCHAR(255) NOT NULL,
  used        BOOLEAN      DEFAULT FALSE,
  created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME     NOT NULL,
  tenant_id   BIGINT,
  PRIMARY KEY (challenge),
  INDEX idx_expires_at (expires_at),
  INDEX idx_tenant_id (tenant_id)
);

-- ── Multi-tenant tables ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  id         BIGINT       NOT NULL AUTO_INCREMENT,
  name       VARCHAR(255) NOT NULL,
  status     ENUM('active','suspended') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS tenant_api_keys (
  id           BIGINT       NOT NULL AUTO_INCREMENT,
  tenant_id    BIGINT       NOT NULL,
  client_id    VARCHAR(100) NOT NULL,
  api_key_hash CHAR(64)     NOT NULL,
  scopes       JSON         NOT NULL,
  active       BOOLEAN      DEFAULT TRUE,
  expires_at   DATETIME,
  created_at   TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  revoked_at   DATETIME,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_client_key (client_id, api_key_hash),
  INDEX idx_client_active (client_id, active, expires_at),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- ── Multi-key identity tables ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS identity (
  id         BIGINT        NOT NULL AUTO_INCREMENT,
  tenant_id  BIGINT        NOT NULL,
  role       ENUM('issuer','holder','verifier') NOT NULL,
  name       VARCHAR(255)  NOT NULL,
  did_method ENUM('did:key','did:web') NOT NULL DEFAULT 'did:key',
  domain     VARCHAR(255),
  did        VARCHAR(512),
  created_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_did (did),
  INDEX idx_tenant_role (tenant_id, role),
  INDEX idx_domain (domain),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS did_keys (
  id              BIGINT        NOT NULL AUTO_INCREMENT,
  identity_id     BIGINT        NOT NULL,
  did             VARCHAR(512)  NOT NULL,
  key_fragment    VARCHAR(255),
  purpose         ENUM('assertionMethod','authentication','capabilityDelegation','capabilityInvocation','keyAgreement') NOT NULL,
  key_version     INT           NOT NULL DEFAULT 1,
  did_document    JSON          NOT NULL,
  enc_private_key TEXT          NOT NULL,
  public_key_jwk  JSON          NOT NULL,
  status          ENUM('active','inactive','revoked') NOT NULL DEFAULT 'active',
  activated_at    DATETIME      NOT NULL,
  expires_at      DATETIME,
  revoked_at      DATETIME,
  created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_did_fragment (did, key_fragment),
  INDEX idx_identity_purpose_status (identity_id, purpose, status),
  FOREIGN KEY (identity_id) REFERENCES identity(id)
);

CREATE TABLE IF NOT EXISTS key_audit_log (
  id            BIGINT        NOT NULL AUTO_INCREMENT,
  tenant_id     BIGINT,
  event_type    ENUM('KEY_CREATED','KEY_ROTATED','KEY_REVOKED','SIGN_VC','SIGN_VP','VERIFY_VP') NOT NULL,
  identity_id   BIGINT,
  did_key_id    BIGINT,
  did           VARCHAR(512),
  actor         VARCHAR(255),
  credential_id VARCHAR(255),
  meta          JSON,
  created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_tenant_id (tenant_id),
  INDEX idx_event_type (event_type, created_at)
);

-- ── Credential status + schema tables ────────────────────────────────────

CREATE TABLE IF NOT EXISTS status_lists (
  id            BIGINT        NOT NULL AUTO_INCREMENT,
  tenant_id     BIGINT        NOT NULL,
  identity_id   BIGINT        NOT NULL,
  list_id       VARCHAR(255)  NOT NULL,
  purpose       ENUM('revocation','suspension') NOT NULL DEFAULT 'revocation',
  encoded_list  MEDIUMTEXT    NOT NULL,
  list_size     INT           NOT NULL DEFAULT 131072,
  next_index    INT           NOT NULL DEFAULT 0,
  vc_id         VARCHAR(512)  NOT NULL,
  signed_vc     JSON,
  created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_list_id (list_id),
  INDEX idx_tenant_identity (tenant_id, identity_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (identity_id) REFERENCES identity(id)
);

CREATE TABLE IF NOT EXISTS credential_schemas (
  id          BIGINT        NOT NULL AUTO_INCREMENT,
  tenant_id   BIGINT        NOT NULL,
  slug        VARCHAR(255)  NOT NULL,
  schema_id   VARCHAR(512)  NOT NULL,
  version     VARCHAR(50)   NOT NULL DEFAULT '1.0.0',
  schema_json JSON          NOT NULL,
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_tenant_slug_version (tenant_id, slug, version),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS issuer_accreditations (
  id             BIGINT        NOT NULL AUTO_INCREMENT,
  tenant_id      BIGINT        NOT NULL,
  identity_id    BIGINT        NOT NULL,
  schema_id      BIGINT        NOT NULL,
  trust_level    ENUM('self-asserted','accredited','government') NOT NULL DEFAULT 'self-asserted',
  accreditor_did VARCHAR(512),
  valid_from     DATETIME      NOT NULL DEFAULT (NOW()),
  valid_until    DATETIME,
  status         ENUM('active','revoked') NOT NULL DEFAULT 'active',
  created_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_identity_schema (identity_id, schema_id),
  INDEX idx_tenant (tenant_id),
  INDEX idx_identity (identity_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (identity_id) REFERENCES identity(id),
  FOREIGN KEY (schema_id) REFERENCES credential_schemas(id)
);
