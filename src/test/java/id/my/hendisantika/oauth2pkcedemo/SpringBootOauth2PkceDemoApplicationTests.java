package id.my.hendisantika.oauth2pkcedemo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class SpringBootOauth2PkceDemoApplicationTests extends AbstractMySqlIntegrationTest {

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	void contextLoads() {
		assertThat(registeredClientRepository).isNotNull();
	}

}
