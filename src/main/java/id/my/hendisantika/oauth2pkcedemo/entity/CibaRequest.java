package id.my.hendisantika.oauth2pkcedemo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
@Entity
@Table(name = "ciba_request")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CibaRequest {

    /** Where a backchannel request is in its life; the client learns this only by polling. */
    public enum Status {
        PENDING, APPROVED, DENIED, CONSUMED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "auth_req_id", nullable = false, length = 200, unique = true)
    private String authReqId;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "principal_name", nullable = false, length = 200)
    private String principalName;

    /** Stored space-delimited, the way they arrive and the way they go back out. */
    @Column(name = "scopes", nullable = false, length = 1000)
    private String scopes;

    /**
     * Shown on both the client and the approving device. The user compares them, which is what stops
     * an attacker starting a request and hoping someone approves it.
     */
    @Column(name = "binding_message", length = 200)
    private String bindingMessage;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private Status status;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "decided_at")
    private Instant decidedAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public Set<String> scopeSet() {
        return new LinkedHashSet<>(Set.of(scopes.split(" ")));
    }
}
