package id.my.hendisantika.oauth2pkcedemo.repository;

import id.my.hendisantika.oauth2pkcedemo.entity.CibaRequest;
import org.springframework.data.jpa.repository.JpaRepository;

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
public interface CibaRequestRepository extends JpaRepository<CibaRequest, Long> {

    Optional<CibaRequest> findByAuthReqId(String authReqId);

    List<CibaRequest> findByPrincipalNameAndStatusOrderByRequestedAtDesc(
            String principalName, CibaRequest.Status status);
}
