package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.02
 */
@Configuration(proxyBeanMethods = false)
public class MtlsConnectorConfig {

    /** Everything else stays on plain HTTP; only the mTLS demo needs a TLS handshake. */
    public static final int MTLS_PORT = 8443;

    @Bean
    public MtlsMaterial mtlsMaterial() {
        return MtlsMaterial.generate();
    }

    /**
     * Adds a second connector that asks for a client certificate. It is deliberately
     * {@code want} rather than {@code need}: a handshake with no certificate must still succeed, so
     * the demo can show the token endpoint refusing that request on its own terms rather than the
     * connection being dropped before OAuth is reached.
     */
    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> mtlsConnectorCustomizer(
            MtlsMaterial material) {
        return factory -> factory.addAdditionalConnectors(mtlsConnector(material));
    }

    private static Connector mtlsConnector(MtlsMaterial material) {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setPort(MTLS_PORT);
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setProperty("SSLEnabled", "true");

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setCertificateVerification("want");
        sslHostConfig.setTruststoreFile(material.getTrustStorePath().toString());
        sslHostConfig.setTruststorePassword(new String(MtlsMaterial.PASSWORD));
        sslHostConfig.setTruststoreType("PKCS12");

        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);
        certificate.setCertificateKeystoreFile(material.getServerKeyStorePath().toString());
        certificate.setCertificateKeystorePassword(new String(MtlsMaterial.PASSWORD));
        certificate.setCertificateKeystoreType("PKCS12");
        certificate.setCertificateKeyAlias("server");
        sslHostConfig.addCertificate(certificate);

        connector.addSslHostConfig(sslHostConfig);
        return connector;
    }
}
