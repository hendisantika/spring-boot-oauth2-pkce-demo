package id.my.hendisantika.oauth2pkcedemo;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.20
 */
public abstract class AbstractMySqlIntegrationTest {

    /**
     * A single MySQL for the whole test JVM, started once and reused by every subclass. The JDBC
     * parameters mirror the ones the application uses, so Flyway runs against the same dialect.
     */
    @ServiceConnection
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:9.6.0")
            .withDatabaseName("oauth2_pkce_demo")
            .withUrlParam("preserveInstants", "true")
            .withUrlParam("connectionTimeZone", "UTC")
            .withUrlParam("forceConnectionTimeZoneToSession", "true");

    static {
        MYSQL.start();
    }
}
