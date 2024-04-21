package stevanovic.dejana.userservice.config;

import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

//TODO: this key should be stored in some safe place
@Component
public class JwtSecretKey {
        private static SecretKey secretKey;

        @PostConstruct
        public void init() {
            secretKey = Jwts.SIG.HS512.key().build();
        }

        public static SecretKey getKey() {
            return secretKey;
        }

}
