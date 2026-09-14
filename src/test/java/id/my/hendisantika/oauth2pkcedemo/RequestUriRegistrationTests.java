package id.my.hendisantika.oauth2pkcedemo;

import com.sun.net.httpserver.HttpServer;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.HostedRequestObjectController;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriFetcher;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 21.30
 */
@SpringBootTest
class RequestUriRegistrationTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private RequestUriPolicy policy;

    @Autowired
    private RegisteredClientRepository registeredClients;

    private HttpServer host;

    @AfterEach
    void tidy() {
        policy.requireRegistration(RequestUriPolicy.REQUIRE_REGISTRATION_DEFAULT);
        if (host != null) {
            host.stop(0);
            host = null;
        }
    }

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * OpenID Connect Discovery defaults this to false. True here, because RFC 9101 section 10.4.1's
     * first mitigation is knowing which locations are expected.
     */
    @Test
    void theRequirementIsOnAndPublished() throws Exception {
        assertThat(RequestUriPolicy.REQUIRE_REGISTRATION_DEFAULT).isTrue();
        assertThat(policy.requireRegistration()).isTrue();

        for (String document : List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            assertThat(mockMvc().perform(get(document))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString())
                    .contains("\"" + ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION
                            + "\":true");
        }
    }

    /** The client's registered request_uris are what "an expected location" means. */
    @Test
    void theClientRegistersTheUrlsItMayBePointedAt() {
        RegisteredClient client = registeredClients
                .findByClientId(properties.fetchedRequestClient().clientId());

        assertThat(client).isNotNull();
        assertThat(String.valueOf(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING)))
                .contains(HostedRequestObjectController.HOSTED_URI)
                .doesNotContain(HostedRequestObjectController.OTHER_CLIENT_URI);
    }

    /**
     * The registration list is per client: one client may not use another's URL, which is what stops
     * the rewrite in RFC 9101 section 10.4.2 from reaching anywhere new.
     */
    @Test
    void anotherClientsRegisteredUrlIsRefusedBeforeAnythingIsFetched() throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.fetchedRequestClient().clientId());
        query.put("request_uri", properties.issuerUri()
                + HostedRequestObjectController.OTHER_CLIENT_URI);

        assertThat(refusal(query))
                .contains("not registered for this client")
                .contains(ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION + " is true");
    }

    /** With the requirement off, the same URL gets as far as being fetched. */
    @Test
    void turningTheRequirementOffLetsTheServerGoThere() throws Exception {
        policy.requireRegistration(false);
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.fetchedRequestClient().clientId());
        query.put("request_uri", properties.issuerUri()
                + HostedRequestObjectController.OTHER_CLIENT_URI);

        // What happens next depends on whether anything is answering the issuer's port, which a test
        // has no business assuming. The decision is the assertion: the registration check no longer
        // speaks, so the server is willing to go. The page shows where going leads.
        assertThat(refusal(query)).doesNotContain("not registered for this client");
    }

    /** RFC 9101 section 5.2: an https URI, with this demo's own http origin the sole exception. */
    @Test
    void aPlainHttpUrlSomewhereElseIsRefused() throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.fetchedRequestClient().clientId());
        query.put("request_uri", "http://elsewhere.example.org/request-object.jwt");

        assertThat(refusal(query)).contains("must be https");
    }

    /** Section 10.4.1 clause (b): check the media type of what came back. */
    @Test
    void aResponseOfTheWrongMediaTypeIsRefused() throws Exception {
        String url = serve("text/plain", "not-a-request-object");

        assertThatThrownBy(() -> new RequestUriFetcher().fetch(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("served text/plain");
    }

    /** And the right one is returned as it stands, trimmed of nothing but whitespace. */
    @Test
    void aResponseOfTheRightMediaTypeIsReturned() throws Exception {
        String url = serve(HostedRequestObjectController.MEDIA_TYPE, "  a.b.c \n");

        assertThat(new RequestUriFetcher().fetch(url)).isEqualTo("a.b.c");
    }

    /** Section 5.2: "The entire Request URI SHOULD NOT exceed 512 ASCII characters." */
    @Test
    void anOverlongUrlIsRefusedWithoutBeingVisited() {
        String url = "https://client.example.org/"
                + "x".repeat(RequestUriFetcher.MAXIMUM_URI_LENGTH);

        assertThatThrownBy(() -> new RequestUriFetcher().fetch(url))
                .hasMessageContaining("longer than " + RequestUriFetcher.MAXIMUM_URI_LENGTH);
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/request-uri-registration")).andExpect(status().isOk());
    }

    /** A one-response host on an ephemeral port, so the fetcher has something real to fetch. */
    private String serve(String contentType, String body) throws IOException {
        host = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        host.createContext("/request-object.jwt", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        host.start();
        return "http://127.0.0.1:" + host.getAddress().getPort() + "/request-object.jwt";
    }

    private MvcResult perform(Map<String, String> query) throws Exception {
        var request = get("/oauth2/authorize").with(user("hendi"));
        query.forEach(request::queryParam);
        return mockMvc().perform(request).andReturn();
    }

    private String refusal(Map<String, String> query) throws Exception {
        MvcResult result = perform(query);
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        return result.getResponse().getContentAsString();
    }
}
