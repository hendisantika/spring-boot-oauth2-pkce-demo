-- Application users that the authorization server authenticates at /login.
CREATE TABLE users
(
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    username   VARCHAR(100) NOT NULL,
    password   VARCHAR(200) NOT NULL,
    full_name  VARCHAR(200) NOT NULL,
    email      VARCHAR(200) NOT NULL,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username (username),
    UNIQUE KEY uk_users_email (email)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

CREATE TABLE user_authorities
(
    user_id   BIGINT       NOT NULL,
    authority VARCHAR(100) NOT NULL,
    PRIMARY KEY (user_id, authority),
    CONSTRAINT fk_user_authorities_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
