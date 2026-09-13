package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.config.MtlsConnectorConfig;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsRefreshAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsRefreshRun;
import id.my.hendisantika.oauth2pkcedemo.security.PendingMtlsRefresh;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 09.12
 */
@Slf4j
@Service
public class MtlsRefreshService {

    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /** The same connection the mTLS page uses: the registered certificate, on the TLS listener. */
    private final RestClient withRegisteredCertificate;

    /** A certificate the transport trusts and the authorization server has never heard of. */
    private final RestClient withStrangerCertificate;

    /** No certificate at all, on the plain listener, which is where everything else here runs. */
    private final RestClient withoutCertificate;

    private final MtlsMaterial material;
    private final DemoProperties properties;

    public MtlsRefreshService(MtlsMaterial material, DemoProperties properties) {
        this.material = material;
        this.properties = properties;
        this.withRegisteredCertificate = restClient(material.getClientKeyStorePath());
        this.withStrangerCertificate = restClient(material.getStrangerKeyStorePath());
        this.withoutCertificate = restClient(null);
    }

    public String clientId() {
        return properties.mtlsRefreshClient().clientId();
    }

    private static String mtlsBase() {
        return "https://localhost:" + MtlsConnectorConfig.MTLS_PORT;
    }

    public String mtlsTokenEndpoint() {
        return mtlsBase() + "/oauth2/token";
    }

    public String plainTokenEndpoint() {
        return properties.issuerUri() + "/oauth2/token";
    }

    public String certificateThumbprint() {
        return material.clientCertificateThumbprint();
    }

    public String strangerThumbprint() {
        return material.strangerCertificateThumbprint();
    }

    /**
     * Asks for device codes over the TLS listener, presenting the certificate - which is also how
     * this client authenticates, there being nothing else it could authenticate with.
     */
    @SuppressWarnings("unchecked")
    public PendingMtlsRefresh start() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());
        form.add(OAuth2ParameterNames.SCOPE, "profile email");

        Map<String, Object> body = withRegisteredCertificate.post()
                .uri(mtlsBase() + "/oauth2/device_authorization")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        if (body == null || body.get("device_code") == null) {
            throw new IllegalStateException("The device authorization endpoint refused the request");
        }
        return new PendingMtlsRefresh(String.valueOf(body.get("device_code")),
                String.valueOf(body.get("user_code")), Instant.now());
    }

    /**
     * Redeems the approved device code over the same connection, then tries to refresh three ways.
     * The refresh token is rotated on every use, so each attempt carries whatever the last
     * successful one returned.
     */
    @SuppressWarnings("unchecked")
    public MtlsRefreshRun run(PendingMtlsRefresh pending) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, DEVICE_CODE_GRANT);
        form.add("device_code", pending.deviceCode());
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());

        Map<String, Object> issued = withRegisteredCertificate.post()
                .uri(mtlsTokenEndpoint())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> response.bodyTo(Map.class), false);
        if (issued == null || issued.get("access_token") == null) {
            throw new IllegalStateException(issued == null
                    ? "The token endpoint said nothing"
                    : "The device code was not redeemable: " + issued.get("error"));
        }

        String refreshToken = issued.get(OAuth2ParameterNames.REFRESH_TOKEN) == null
                ? null : String.valueOf(issued.get(OAuth2ParameterNames.REFRESH_TOKEN));

        List<MtlsRefreshAttempt> attempts = new ArrayList<>();
        if (refreshToken != null) {
            attempts.add(refresh("With a certificate the server does not know",
                    "Trusted by the transport, so the request arrives; registered to nobody.",
                    withStrangerCertificate, mtlsTokenEndpoint(), refreshToken));
            attempts.add(refresh("With no certificate at all",
                    "The same request on the plain listener, where every other page here runs.",
                    withoutCertificate, plainTokenEndpoint(), refreshToken));
            attempts.add(refresh("With the registered certificate",
                    "The connection the tokens were issued over.",
                    withRegisteredCertificate, mtlsTokenEndpoint(), refreshToken));
        }

        log.debug("mTLS refresh run finished for {}", clientId());
        return new MtlsRefreshRun(clientId(), certificateThumbprint(), strangerThumbprint(),
                confirmationOf(String.valueOf(issued.get("access_token"))),
                refreshToken != null, attempts, Instant.now());
    }

    @SuppressWarnings("unchecked")
    private MtlsRefreshAttempt refresh(String label, String description, RestClient restClient,
                                       String uri, String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        form.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        form.add(OAuth2ParameterNames.CLIENT_ID, clientId());

        try {
            return restClient.post()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        Map<String, Object> body = response.bodyTo(Map.class);
                        if (status != 200 || body == null || body.get("access_token") == null) {
                            return new MtlsRefreshAttempt(label, description, status, null,
                                    body == null ? "Refused." : "Refused: " + body.get("error"));
                        }
                        String confirmation = confirmationOf(String.valueOf(body.get("access_token")));
                        return new MtlsRefreshAttempt(label, description, status, confirmation,
                                "A new access token, bound to the same certificate.");
                    }, false);
        } catch (Exception ex) {
            // A handshake that never completed says nothing about what the server checks, so it is
            // reported as what it is rather than folded in with the refusals.
            return new MtlsRefreshAttempt(label, description, 0, null,
                    "The connection was not established: " + ex.getMessage());
        }
    }

    /** RFC 8705 section 3.1: the thumbprint the token is bound to, when it is bound to anything. */
    @SuppressWarnings("unchecked")
    private static String confirmationOf(String accessToken) {
        try {
            Object cnf = JWTParser.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
            return cnf instanceof Map<?, ?> map
                    ? String.valueOf(((Map<String, Object>) map).get("x5t#S256")) : null;
        } catch (Exception ex) {
            return null;
        }
    }

    /** @param keyStorePath the certificate to present, or {@code null} to present none */
    private RestClient restClient(Path keyStorePath) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManagerFactory trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(load(material.getTrustStorePath()));

            KeyManagerFactory keyManagers = null;
            if (keyStorePath != null) {
                keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(load(keyStorePath), MtlsMaterial.PASSWORD);
            }
            sslContext.init(keyManagers == null ? null : keyManagers.getKeyManagers(),
                    trustManagers.getTrustManagers(), null);

            return RestClient.builder()
                    .requestFactory(new JdkClientHttpRequestFactory(
                            HttpClient.newBuilder().sslContext(sslContext).build()))
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to build the mTLS client", ex);
        }
    }

    private static KeyStore load(Path path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, MtlsMaterial.PASSWORD);
        }
        return keyStore;
    }
}
