package stevanovic.dejana.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import stevanovic.dejana.userservice.model.UserData;

public interface UserRepository extends JpaRepository<UserData, Long> {
    UserData findByUsername(String username);
}