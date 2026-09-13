package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.ClientFrontChannelLogoutController;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelLogoutRun;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelLogoutTarget;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelProbe;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
@Slf4j
@Service
public class FrontChannelLogoutService {

    /** A port nothing listens on, for the iframe that never reaches anybody. */
    private static final String UNREACHABLE_CLIENT = "http://localhost:9/frontchannel/logout/gone";

    private static final int RETAINED_RUNS = 16;

    /** A run ends with the session gone, so what happened cannot be kept in it. */
    private final Map<String, FrontChannelLogoutRun> runs =
            Collections.synchronizedMap(new LinkedHashMap<>() {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, FrontChannelLogoutRun> eldest) {
                    return size() > RETAINED_RUNS;
                }
            });

    private final RestClient restClient;
    private final DemoProperties properties;

    public FrontChannelLogoutService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public FrontChannelLogoutRun find(String id) {
        return id == null ? null : this.runs.get(id);
    }

    /**
     * The clients this server would tell. In a deployment these come from each registration's
     * {@code frontchannel_logout_uri}; both browser clients here have one, and one of them asks for
     * the session to be named so the difference is visible.
     */
    public List<FrontChannelLogoutTarget> targets(String sessionId) {
        List<FrontChannelLogoutTarget> targets = new ArrayList<>();
        targets.add(target(properties.client(), true, sessionId));
        targets.add(target(properties.confidentialClient(), false, sessionId));
        return targets;
    }

    private FrontChannelLogoutTarget target(DemoProperties.Client client, boolean sessionRequired,
                                            String sessionId) {
        String uri = properties.issuerUri()
                + ClientFrontChannelLogoutController.LOGOUT_URI + client.registrationId();
        if (sessionRequired) {
            uri = UriComponentsBuilder.fromUriString(uri)
                    .queryParam(ClientFrontChannelLogoutController.ISSUER, properties.issuerUri())
                    .queryParam(ClientFrontChannelLogoutController.SESSION_ID, sessionId)
                    .build()
                    .encode()
                    .toUriString();
        }
        return new FrontChannelLogoutTarget(client.clientName(), client.registrationId(), uri,
                sessionRequired);
    }

    /**
     * What the authorization server renders when a session ends: a page of iframes, one per client,
     * loaded by the browser that is signing out. The browser is the only thing that can reach every
     * client with its own cookies attached, and it is also the reason none of this can be relied on.
     */
    public String document(List<FrontChannelLogoutTarget> targets) {
        StringBuilder html = new StringBuilder("""
                <!DOCTYPE html>
                <html>
                <head><title>Logging out</title></head>
                <body>
                """);
        for (FrontChannelLogoutTarget target : targets) {
            html.append("  <iframe src=\"")
                    .append(HtmlUtils.htmlEscape(target.uri()))
                    .append("\" style=\"display:none\"></iframe>\n");
        }
        html.append("</body>\n</html>\n");
        return html.toString();
    }

    /**
     * The same URIs, fetched by this server rather than by the browser. Nothing about the requests
     * is malformed; they simply arrive without the cookies that say whose session this is - which is
     * what a browser blocking third-party cookies produces, and what a client cannot tell apart from
     * a user who was never signed in.
     */
    public List<FrontChannelProbe> probeWithoutCookies(List<FrontChannelLogoutTarget> targets) {
        List<FrontChannelProbe> probes = new ArrayList<>();
        for (FrontChannelLogoutTarget target : targets) {
            probes.add(fetch(target.clientName(), "The iframe loads, but with no cookie attached.",
                    target.uri()));
        }
        probes.add(fetch("A client that is not there",
                "An iframe pointing at a host that refuses the connection.",
                UNREACHABLE_CLIENT));
        return probes;
    }

    private FrontChannelProbe fetch(String label, String description, String uri) {
        try {
            return this.restClient.get()
                    .uri(uri)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        String body = response.bodyTo(String.class);
                        return new FrontChannelProbe(label, description, status,
                                body == null || body.isBlank() ? "(no body)" : body.trim());
                    }, false);
        } catch (Exception ex) {
            // A browser loading this iframe would show nothing and carry on. So does everything else.
            return new FrontChannelProbe(label, description, 0, "the request never arrived");
        }
    }

    /** Keeps a run so the page can show it after the session that produced it has gone. */
    public String record(List<FrontChannelLogoutTarget> targets, List<FrontChannelProbe> probes,
                         String sessionId) {
        String id = UUID.randomUUID().toString();
        this.runs.put(id, new FrontChannelLogoutRun(targets, document(targets), probes, sessionId,
                Instant.now()));
        log.debug("Front-channel logout run {} for sid={} with {} target(s)",
                id, sessionId, targets.size());
        return id;
    }
}
