package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationServerMetadataService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.12
 */
@Controller
@RequiredArgsConstructor
public class AuthorizationServerMetadataController {

    /** An issuer with a path component, to show the well-known rule that only then differs. */
    private static final String TENANTED_ISSUER = "https://example.com/tenant1";

    private final AuthorizationServerMetadataService metadataService;
    private final DemoProperties properties;

    /**
     * Reads both documents over HTTP rather than from the beans that build them. What a client can
     * see is the only thing that matters here, and a self-call is exactly what a client would do -
     * just not during startup, which is why this application configures its own registrations by
     * hand.
     */
    @GetMapping("/metadata")
    public String metadataPage(Model model) {
        String issuer = properties.issuerUri();
        String oauthUri = AuthorizationServerMetadataService.wellKnownUri(
                issuer, AuthorizationServerMetadataService.OAUTH_SUFFIX);
        String oidcUri = AuthorizationServerMetadataService.openIdConnectUri(
                issuer, AuthorizationServerMetadataService.OIDC_SUFFIX);

        Map<String, Object> oauthDocument = metadataService.fetch(oauthUri);
        Map<String, Object> oidcDocument = metadataService.fetch(oidcUri);

        model.addAttribute("issuer", issuer);
        model.addAttribute("oauthUri", oauthUri);
        model.addAttribute("oidcUri", oidcUri);
        model.addAttribute("entries", metadataService.describe(oauthDocument, oidcDocument));
        model.addAttribute("comparison", metadataService.compare(oauthDocument, oidcDocument));
        model.addAttribute("attempts", metadataService.discover());
        model.addAttribute("configured", metadataService.configuredFrom(oauthDocument));
        model.addAttribute("httpsIssuer", issuer.startsWith("https://"));

        // The two rules agree for an issuer with no path, and only then.
        model.addAttribute("tenantedIssuer", TENANTED_ISSUER);
        model.addAttribute("tenantedOauthUri", AuthorizationServerMetadataService.wellKnownUri(
                TENANTED_ISSUER, AuthorizationServerMetadataService.OAUTH_SUFFIX));
        model.addAttribute("tenantedOidcUri", AuthorizationServerMetadataService.openIdConnectUri(
                TENANTED_ISSUER, AuthorizationServerMetadataService.OIDC_SUFFIX));
        return "metadata";
    }
}
