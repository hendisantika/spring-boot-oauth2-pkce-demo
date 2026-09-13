-- Client-side token store. Schema taken from spring-security-oauth2-client 7.1.1
-- (oauth2-client-schema.sql), so the access/refresh tokens this app receives as an
-- OAuth2 client are persisted in MySQL instead of being held in memory.

CREATE TABLE oauth2_authorized_client
(
    client_registration_id  VARCHAR(100)  NOT NULL,
    principal_name          VARCHAR(200)  NOT NULL,
    access_token_type       VARCHAR(100)  NOT NULL,
    access_token_value      BLOB          NOT NULL,
    access_token_issued_at  TIMESTAMP     NOT NULL,
    access_token_expires_at TIMESTAMP     NOT NULL,
    access_token_scopes     VARCHAR(1000) NULL     DEFAULT NULL,
    refresh_token_value     BLOB          NULL     DEFAULT NULL,
    refresh_token_issued_at TIMESTAMP     NULL     DEFAULT NULL,
    created_at              TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_registration_id, principal_name)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
