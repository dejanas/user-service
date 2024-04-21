package stevanovic.dejana.userservice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import stevanovic.dejana.userservice.dto.AuthRequest;
import stevanovic.dejana.userservice.model.Role;
import stevanovic.dejana.userservice.model.UserData;
import stevanovic.dejana.userservice.repository.UserRepository;
import stevanovic.dejana.userservice.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final JwtTokenUtil jwtUtil;
    private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        final UserData user = userRepository.findByUsername(authRequest.getUsername());
        final String jwt = jwtUtil.generateToken(user);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", jwt);
        return ResponseEntity.ok().headers(headers).build();
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest authRequest) {
        if (userRepository.findByUsername(authRequest.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Username is already taken");
        }
        UserData user = new UserData();
        user.setUsername(authRequest.getUsername());
        user.setPassword(passwordEncoder.encode(authRequest.getPassword()));
        user.setRoles(Role.USER.name() + "," + Role.ADMIN.name());
        userRepository.save(user);
        return ResponseEntity.ok("UserData registered successfully");
    }

    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String jwtToken) {
        if (jwtUtil.validateToken(jwtToken)) {
            return ResponseEntity.ok("User token validated successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/admin/validate-token")
    public ResponseEntity<?> validateAdminToken(@RequestHeader("Authorization") String jwtToken) {
        if (jwtUtil.validateAdminToken(jwtToken)) {
            return ResponseEntity.ok("Admin token validated successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/admin/validate-owner-token")
    public ResponseEntity<?> validateOwnerToken(@RequestHeader("Authorization") String jwtToken,
                                                @RequestBody Long userId) {
        if (jwtUtil.validateOwnerToken(jwtToken, userId)) {
            return ResponseEntity.ok("Owner token validated successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
