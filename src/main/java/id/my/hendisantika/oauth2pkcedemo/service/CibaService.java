package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.entity.CibaRequest;
import id.my.hendisantika.oauth2pkcedemo.repository.CibaRequestRepository;
import id.my.hendisantika.oauth2pkcedemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CibaService {

    public static final Duration LIFETIME = Duration.ofMinutes(5);
    public static final int POLL_INTERVAL_SECONDS = 5;

    private final StringKeyGenerator authReqIdGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 48);

    private final CibaRequestRepository cibaRequestRepository;
    private final UserRepository userRepository;

    /**
     * Opens a backchannel request. Unlike every other flow here, the client names the user itself
     * with a hint and the user is never sent anywhere - approval arrives out of band.
     *
     * @param loginHint identifies the user the client wants to authenticate
     * @throws IllegalArgumentException when the hint names nobody, which the endpoint reports as
     *                                  {@code unknown_user_id}
     */
    @Transactional
    public CibaRequest start(String clientId, String loginHint, String scopes, String bindingMessage) {
        String principalName = userRepository.findByUsername(loginHint)
                .orElseThrow(() -> new IllegalArgumentException("No user matches login_hint " + loginHint))
                .getUsername();

        Instant now = Instant.now();
        CibaRequest request = CibaRequest.builder()
                .authReqId(authReqIdGenerator.generateKey())
                .clientId(clientId)
                .principalName(principalName)
                .scopes(scopes)
                .bindingMessage(bindingMessage)
                .status(CibaRequest.Status.PENDING)
                .requestedAt(now)
                .expiresAt(now.plus(LIFETIME))
                .build();
        log.debug("Opened CIBA request for [{}] from client [{}]", principalName, clientId);
        return cibaRequestRepository.save(request);
    }

    @Transactional(readOnly = true)
    public List<CibaRequest> pendingFor(String principalName) {
        return cibaRequestRepository
                .findByPrincipalNameAndStatusOrderByRequestedAtDesc(principalName, CibaRequest.Status.PENDING)
                .stream()
                .filter(request -> !request.isExpired())
                .toList();
    }

    @Transactional
    public void decide(String authReqId, String principalName, boolean approved) {
        cibaRequestRepository.findByAuthReqId(authReqId)
                // Only the user the request names may answer it.
                .filter(request -> request.getPrincipalName().equals(principalName))
                .filter(request -> request.getStatus() == CibaRequest.Status.PENDING)
                .ifPresent(request -> {
                    request.setStatus(approved ? CibaRequest.Status.APPROVED : CibaRequest.Status.DENIED);
                    request.setDecidedAt(Instant.now());
                    cibaRequestRepository.save(request);
                    log.debug("CIBA request {} {}", authReqId, approved ? "approved" : "denied");
                });
    }

    @Transactional(readOnly = true)
    public Optional<CibaRequest> find(String authReqId) {
        return cibaRequestRepository.findByAuthReqId(authReqId);
    }

    /** Marks an approved request as spent, so one approval yields exactly one token. */
    @Transactional
    public void markConsumed(CibaRequest request) {
        request.setStatus(CibaRequest.Status.CONSUMED);
        cibaRequestRepository.save(request);
    }
}
