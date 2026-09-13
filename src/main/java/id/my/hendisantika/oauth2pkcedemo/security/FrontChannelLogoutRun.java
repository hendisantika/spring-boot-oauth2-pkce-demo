package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
public record FrontChannelLogoutRun(List<FrontChannelLogoutTarget> targets,
                                    String document,
                                    List<FrontChannelProbe> probes,
                                    String sessionId,
                                    Instant ranAt) implements Serializable {
}
