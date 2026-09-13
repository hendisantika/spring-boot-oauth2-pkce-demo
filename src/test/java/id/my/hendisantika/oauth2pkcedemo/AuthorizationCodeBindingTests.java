package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.AuthorizationCodeBindingController;
import id.my.hendisantika.oauth2pkcedemo.security.DpopBoundAuthorizationCodeFilter;
import id.my.hendisantika.oauth2pkcedemo.security.PendingCodeBinding;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationCodeBindingService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
@SpringBootTest
class AuthorizationCodeBindingTests extends AbstractMySqlIntegrationTest {

    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String CODE = "an-outstanding-authorization-code";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private AuthorizationCodeBindingService bindingService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void aCodeBoundToAKeyIsRefusedWhenTheTokenRequestCarriesNoProof() throws Exception {
        ECKey key = generateKey();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedTheTokenEndpoint = new AtomicBoolean();

        filterFor(thumbprintOf(key))
                .doFilter(tokenRequest(null), response, chainRecording(reachedTheTokenEndpoint));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("invalid_grant").contains("no DPoP proof");
        // The token endpoint never sees it, so the code is still there to be redeemed properly.
        assertThat(reachedTheTokenEndpoint).isFalse();
    }

    @Test
    void aCodeBoundToAKeyIsRefusedWhenTheProofComesFromAnotherKey() throws Exception {
        ECKey key = generateKey();
        ECKey attackerKey = generateKey();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedTheTokenEndpoint = new AtomicBoolean();

        filterFor(thumbprintOf(key)).doFilter(tokenRequest(proof(attackerKey, attackerKey)), response,
                chainRecording(reachedTheTokenEndpoint));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString())
                .contains(thumbprintOf(key))
                .contains(thumbprintOf(attackerKey));
        assertThat(reachedTheTokenEndpoint).isFalse();
    }

    /**
     * The thumbprint is public, so a proof can always be made to <em>claim</em> the right key. What
     * it cannot be made to do is verify against it.
     */
    @Test
    void aProofCarryingSomeoneElsesPublicKeyDoesNotVerify() throws Exception {
        ECKey key = generateKey();
        ECKey attackerKey = generateKey();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedTheTokenEndpoint = new AtomicBoolean();

        // The victim's public key in the header, the attacker's private key on the signature.
        filterFor(thumbprintOf(key)).doFilter(tokenRequest(proof(key, attackerKey)), response,
                chainRecording(reachedTheTokenEndpoint));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentAsString()).contains("signature does not verify");
        assertThat(reachedTheTokenEndpoint).isFalse();
    }

    @Test
    void aProofFromTheBoundKeyIsLetThrough() throws Exception {
        ECKey key = generateKey();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedTheTokenEndpoint = new AtomicBoolean();

        filterFor(thumbprintOf(key))
                .doFilter(tokenRequest(proof(key, key)), response, chainRecording(reachedTheTokenEndpoint));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(reachedTheTokenEndpoint).isTrue();
    }

    @Test
    void aCodeThatNamedNoKeyIsLeftToTheTokenEndpoint() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedTheTokenEndpoint = new AtomicBoolean();

        filterFor(null).doFilter(tokenRequest(null), response, chainRecording(reachedTheTokenEndpoint));

        // Nothing was asked for, so there is nothing to enforce - RFC 9449 section 10 is optional.
        assertThat(reachedTheTokenEndpoint).isTrue();
    }

    @Test
    void onlyTheBoundRunNamesAKeyInItsAuthorizationRequest() {
        Map<String, String> bound = bindingService.authorizationParameters(bindingService.start(true));
        Map<String, String> unbound = bindingService.authorizationParameters(bindingService.start(false));

        assertThat(bound).containsKey(DpopBoundAuthorizationCodeFilter.DPOP_JKT);
        assertThat(unbound).doesNotContainKey(DpopBoundAuthorizationCodeFilter.DPOP_JKT);
        // Both still use PKCE: dpop_jkt is a second binding, not a replacement.
        assertThat(bound).containsEntry("code_challenge_method", "S256");
        assertThat(unbound).containsEntry("code_challenge_method", "S256");
    }

    /**
     * RFC 9449 section 10: the parameter "only provides similar protections when a unique DPoP key
     * is used for each authorization request".
     */
    @Test
    void everyRunBindsItsCodeToAKeyOfItsOwn() {
        PendingCodeBinding first = bindingService.start(true);
        PendingCodeBinding second = bindingService.start(true);

        assertThat(first.thumbprint()).isNotEqualTo(second.thumbprint());
        assertThat(first.codeVerifier()).isNotEqualTo(second.codeVerifier());
        assertThat(first.state()).isNotEqualTo(second.state());
    }

    @Test
    void theCodeBindingClientIsPublicRequiresPkceAndOwnsItsCallback() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.codeBindingClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getRedirectUris())
                .containsExactly(properties.issuerUri() + AuthorizationCodeBindingController.CALLBACK_URI);
    }

    @Test
    void theCodeBindingPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/code-binding")).andExpect(status().isOk());
    }

    /**
     * A filter whose authorization store holds one outstanding code, bound to the given thumbprint
     * or to nothing at all.
     */
    private DpopBoundAuthorizationCodeFilter filterFor(String boundThumbprint) {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.codeBindingClient().clientId());
        OAuth2AuthorizationRequest.Builder authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(properties.issuerUri() + "/oauth2/authorize")
                .clientId(client.getClientId())
                .redirectUri(properties.issuerUri() + AuthorizationCodeBindingController.CALLBACK_URI)
                .state(UUID.randomUUID().toString());
        if (boundThumbprint != null) {
            authorizationRequest.additionalParameters(
                    Map.of(DpopBoundAuthorizationCodeFilter.DPOP_JKT, boundThumbprint));
        }

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("hendi")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest.build())
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, CODE,
                        Instant.now(), Instant.now().plusSeconds(60)))
                .build();

        return new DpopBoundAuthorizationCodeFilter(TOKEN_ENDPOINT, storeHolding(authorization));
    }

    /** An authorization store with exactly one thing in it, looked up by any token value. */
    private static OAuth2AuthorizationService storeHolding(OAuth2Authorization authorization) {
        return new OAuth2AuthorizationService() {
            @Override
            public void save(OAuth2Authorization toSave) {
            }

            @Override
            public void remove(OAuth2Authorization toRemove) {
            }

            @Override
            public OAuth2Authorization findById(String id) {
                return authorization;
            }

            @Override
            public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
                return authorization;
            }
        };
    }

    private static FilterChain chainRecording(AtomicBoolean reached) {
        return (request, response) -> reached.set(true);
    }

    private MockHttpServletRequest tokenRequest(String proof) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", TOKEN_ENDPOINT);
        request.setParameter("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        request.setParameter("code", CODE);
        request.setParameter("client_id", properties.codeBindingClient().clientId());
        if (proof != null) {
            request.addHeader("DPoP", proof);
        }
        return request;
    }

    private static ECKey generateKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    }

    private static String thumbprintOf(ECKey key) throws Exception {
        return key.toPublicJWK().computeThumbprint().toString();
    }

    /**
     * @param announced the public key the proof claims to speak for
     * @param signing   the key it is actually signed with - the same one, unless the test is forging
     */
    private static String proof(ECKey announced, ECKey signing) throws Exception {
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("dpop+jwt"))
                        .jwk(announced.toPublicJWK())
                        .build(),
                new JWTClaimsSet.Builder()
                        .jwtID(UUID.randomUUID().toString())
                        .claim("htm", "POST")
                        .claim("htu", "http://localhost" + TOKEN_ENDPOINT)
                        .issueTime(Date.from(Instant.now()))
                        .build());
        proof.sign(new ECDSASigner(signing));
        return proof.serialize();
    }
}
