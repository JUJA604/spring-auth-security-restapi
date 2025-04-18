package project.auth.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import project.auth.security.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
}
