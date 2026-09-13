package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.OpBrowserState;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.25
 */
@Controller
@RequiredArgsConstructor
public class CheckSessionIframeController {

    /** OpenID Connect Session Management section 3.3: the URL a client loads in a hidden iframe. */
    public static final String URI = "/oauth2/check-session";

    /**
     * The OP iframe. It is a page rather than an endpoint: a client embeds it, and from then on the
     * two talk by {@code postMessage} without another request reaching this server. Everything it
     * does happens in the browser, which is the point and also the weakness - it can only answer
     * while it can still read the authorization server's cookie.
     * <p>
     * The script is the specification's own pseudo-code from section 3.2, written out: take the
     * client id and session state out of the message, pull the salt off the end, recompute the hash
     * from the cookie this page can see, and answer {@code unchanged}, {@code changed} or
     * {@code error}.
     */
    @GetMapping(URI)
    @ResponseBody
    public ResponseEntity<String> checkSessionIframe() {
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body("""
                        <!DOCTYPE html>
                        <html>
                        <head><title>check_session_iframe</title></head>
                        <body>
                        <script>
                        function opBrowserState() {
                          const match = document.cookie.match(/(?:^|; )%s=([^;]*)/);
                          return match ? decodeURIComponent(match[1]) : '';
                        }

                        async function sha256Hex(value) {
                          const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
                          return Array.from(new Uint8Array(digest))
                            .map(byte => byte.toString(16).padStart(2, '0')).join('');
                        }

                        window.addEventListener('message', async function (event) {
                          // Section 6: the caller has to be somewhere this server expects.
                          if (event.origin !== window.location.origin) {
                            event.source.postMessage('error', event.origin);
                            return;
                          }
                          const separator = String(event.data).lastIndexOf(' ');
                          if (separator < 0) {
                            event.source.postMessage('error', event.origin);
                            return;
                          }
                          const clientId = String(event.data).substring(0, separator);
                          const sessionState = String(event.data).substring(separator + 1);
                          const salt = sessionState.split('.')[1];
                          if (!salt) {
                            event.source.postMessage('error', event.origin);
                            return;
                          }

                          const recomputed = await sha256Hex(
                            clientId + ' ' + event.origin + ' ' + opBrowserState() + ' ' + salt) + '.' + salt;
                          event.source.postMessage(sessionState === recomputed ? 'unchanged' : 'changed',
                            event.origin);
                        }, false);
                        </script>
                        </body>
                        </html>
                        """.formatted(OpBrowserState.COOKIE_NAME));
    }
}
