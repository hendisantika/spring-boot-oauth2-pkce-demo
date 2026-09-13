package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.config.MtlsConnectorConfig;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsAttempt;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
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
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.02
 */
@Slf4j
@Service
public class MtlsService {

    private final MtlsMaterial material;
    private final DemoProperties properties;

    /** Presents the client certificate on the handshake. */
    private final RestClient withCertificate;

    /** Trusts the same server but offers nothing, which is why the connector asks rather than demands. */
    private final RestClient withoutCertificate;

    public MtlsService(MtlsMaterial material, DemoProperties properties) {
        this.material = material;
        this.properties = properties;
        this.withCertificate = restClient(true);
        this.withoutCertificate = restClient(false);
    }

    public String tokenEndpoint() {
        return "https://localhost:" + MtlsConnectorConfig.MTLS_PORT + "/oauth2/token";
    }

    /**
     * Asks for a token twice over the same TLS endpoint: once presenting the client certificate,
     * once without it. The request bodies are identical - only the handshake differs.
     */
    public List<MtlsAttempt> run() {
        return List.of(
                attempt(withCertificate, "Presenting the client certificate",
                        "The TLS handshake carries the certificate; the request body names only the client id."),
                attempt(withoutCertificate, "Without a certificate",
                        "Identical request, but the handshake offers nothing to identify the caller."));
    }

    private MtlsAttempt attempt(RestClient restClient, String label, String description) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", String.join(" ", properties.mtlsClient().scopes()));
        form.add("client_id", properties.mtlsClient().clientId());
        // No secret and no assertion: the transport is the credential.

        try {
            return restClient.post()
                    .uri(tokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> {
                        String body = response.bodyTo(String.class);
                        int status = response.getStatusCode().value();
                        log.debug("mTLS attempt [{}] -> {}", label, status);
                        return new MtlsAttempt(label, description, status, describe(status, body),
                                status == 200 ? boundThumbprint(body) : null);
                    }, false);
        } catch (Exception ex) {
            return new MtlsAttempt(label, description, 0,
                    ex.getClass().getSimpleName() + ": " + ex.getMessage(), null);
        }
    }

    /**
     * With no client authentication at all there is nothing for the authorization server to reject
     * as a client, so the request falls through to the ordinary "who are you" handling and is sent
     * to the login page. Saying that plainly beats printing a bare 302.
     */
    private static String describe(int status, String body) {
        if (status == 200) {
            return "Access token issued, bound to the certificate.";
        }
        if (status / 100 == 3) {
            return "Redirected to the login page - the request never authenticated as a client.";
        }
        return body == null || body.isBlank() ? "(empty)" : body;
    }

    /** Pulls cnf.x5t#S256 out of the issued token so the page can show it matching the certificate. */
    @SuppressWarnings("unchecked")
    private static String boundThumbprint(String tokenResponse) {
        try {
            int start = tokenResponse.indexOf("\"access_token\":\"") + 16;
            String accessToken = tokenResponse.substring(start, tokenResponse.indexOf('"', start));
            Object cnf = JWTParser.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
            return cnf instanceof Map<?, ?> map ? String.valueOf(map.get("x5t#S256")) : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private RestClient restClient(boolean presentCertificate) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            KeyStore trustStore = load(material.getTrustStorePath());
            TrustManagerFactory trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);

            KeyManagerFactory keyManagers = null;
            if (presentCertificate) {
                keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(load(material.getClientKeyStorePath()), MtlsMaterial.PASSWORD);
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

    private static KeyStore load(java.nio.file.Path path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, MtlsMaterial.PASSWORD);
        }
        return keyStore;
    }
}
