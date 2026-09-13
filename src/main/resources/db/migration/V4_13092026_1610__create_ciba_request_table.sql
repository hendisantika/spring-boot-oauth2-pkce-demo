-- Backchannel authentication requests (OpenID Connect CIBA Core 1.0).
-- Spring Authorization Server has no CIBA support, so the pending requests need a home of their
-- own rather than riding along in oauth2_authorization.

CREATE TABLE ciba_request
(
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    auth_req_id     VARCHAR(200) NOT NULL,
    client_id       VARCHAR(100) NOT NULL,
    principal_name  VARCHAR(200) NOT NULL,
    scopes          VARCHAR(1000) NOT NULL,
    binding_message VARCHAR(200) NULL DEFAULT NULL,
    status          VARCHAR(20)  NOT NULL,
    requested_at    DATETIME(6)  NOT NULL,
    expires_at      DATETIME(6)  NOT NULL,
    decided_at      DATETIME(6)  NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_ciba_request_auth_req_id (auth_req_id),
    KEY idx_ciba_request_principal (principal_name, status)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
