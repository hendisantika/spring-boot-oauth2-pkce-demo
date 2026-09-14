package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 21.30
 */
@Slf4j
public final class RequestUriFetcher {

    /** RFC 9101 section 10.8, and what section 10.4.1 clause (b) says to check the response for. */
    public static final MediaType REQUEST_OBJECT_MEDIA_TYPE =
            new MediaType("application", JwtSecuredAuthorizationRequestFilter.REQUEST_OBJECT_TYPE);

    /** RFC 9101 section 5.2: "The entire Request URI SHOULD NOT exceed 512 ASCII characters." */
    public static final int MAXIMUM_URI_LENGTH = 512;

    /** Clause (c): a timeout, so a slow host cannot hold an authorization request open. */
    public static final Duration TIMEOUT = Duration.ofSeconds(2);

    /** Nothing about a request object needs more room than this. */
    public static final int MAXIMUM_BYTES = 64 * 1024;

    private final RestClient restClient;

    public RequestUriFetcher() {
        // Redirects are not followed: a fetch that can be bounced elsewhere is a fetch whose
        // destination the registered list no longer describes.
        this.restClient = RestClient.builder()
                .requestFactory(new JdkClientHttpRequestFactory(HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .connectTimeout(TIMEOUT)
                        .build()))
                .build();
    }

    /**
     * RFC 9101 section 5.2.3: a GET to the request_uri, and what comes back is the request object.
     *
     * @throws IllegalArgumentException with a description the client is allowed to see
     */
    public String fetch(String requestUri) {
        if (requestUri.length() > MAXIMUM_URI_LENGTH) {
            throw new IllegalArgumentException("The request_uri is longer than "
                    + MAXIMUM_URI_LENGTH + " characters");
        }

        try {
            return this.restClient.get()
                    .uri(URI.create(requestUri))
                    // Anything, deliberately. Asking only for the request object media type would
                    // have the host refuse to serve anything else, and RFC 9101 section 10.4.1
                    // clause (b) is about checking what came back rather than about what was asked
                    // for - a server that never sees the wrong type never learns to refuse it.
                    .accept(MediaType.ALL)
                    .exchange((request, response) -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            throw new IllegalArgumentException("The request_uri answered "
                                    + response.getStatusCode().value());
                        }
                        MediaType contentType = response.getHeaders().getContentType();
                        if (contentType == null
                                || !REQUEST_OBJECT_MEDIA_TYPE.isCompatibleWith(contentType)) {
                            // Section 10.4.1 clause (b). A server that fetches whatever is served and
                            // tries to parse it is a server that can be handed anything at all.
                            throw new IllegalArgumentException("The request_uri served "
                                    + contentType + " rather than " + REQUEST_OBJECT_MEDIA_TYPE);
                        }
                        long length = response.getHeaders().getContentLength();
                        if (length > MAXIMUM_BYTES) {
                            throw new IllegalArgumentException("The request_uri served "
                                    + length + " bytes");
                        }
                        String body = response.bodyTo(String.class);
                        if (body == null || body.isBlank()) {
                            throw new IllegalArgumentException("The request_uri served nothing");
                        }
                        if (body.length() > MAXIMUM_BYTES) {
                            throw new IllegalArgumentException("The request_uri served more than "
                                    + MAXIMUM_BYTES + " bytes");
                        }
                        log.debug("Fetched a request object of {} characters from {}",
                                body.length(), requestUri);
                        return body.trim();
                    }, false);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("The request_uri could not be fetched: "
                    + ex.getMessage());
        }
    }
}
