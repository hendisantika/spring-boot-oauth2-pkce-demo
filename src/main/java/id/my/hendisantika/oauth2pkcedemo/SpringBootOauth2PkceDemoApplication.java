package id.my.hendisantika.oauth2pkcedemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SpringBootOauth2PkceDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootOauth2PkceDemoApplication.class, args);
	}

}
