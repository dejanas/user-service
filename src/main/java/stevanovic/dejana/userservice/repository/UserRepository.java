package stevanovic.dejana.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import stevanovic.dejana.userservice.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}