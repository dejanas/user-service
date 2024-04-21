package stevanovic.dejana.userservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import stevanovic.dejana.userservice.config.JwtSecretKey;
import stevanovic.dejana.userservice.model.Role;
import stevanovic.dejana.userservice.model.User;
import stevanovic.dejana.userservice.repository.UserRepository;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    private final UserRepository userRepository;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public List<String> getRolesFromToken(String jwtToken) {
        List<String> roles = new ArrayList<>();

        Claims claims = getAllClaimsFromToken(jwtToken);

        if (claims.containsKey("roles")) {
            List<String> rolesClaim = claims.get("roles", ArrayList.class);
            roles.addAll(rolesClaim);
        }

        return roles;
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(JwtSecretKey.getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        Object[] roles = user.getRoles().split(",");
        claims.put("roles", roles);
        return doGenerateToken(claims, user.getUsername());
    }

    //TODO: switch deprecated methods
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, JwtSecretKey.getKey()).compact();
    }

    //TODO: refactor
    public Boolean validateToken(String token) {
        String formattedToken = token.replace("Bearer ", "");
        final String username = getUsernameFromToken(formattedToken);
        return (userRepository.findByUsername(username) != null && !isTokenExpired(formattedToken));
    }

    public Boolean validateAdminToken(String token) {
        String formattedToken = token.replace("Bearer ", "");
        final String username = getUsernameFromToken(formattedToken);
        return (userRepository.findByUsername(username) != null &&
                !isTokenExpired(formattedToken) &&
                getRolesFromToken(formattedToken).contains(Role.ADMIN.name()));
    }
}