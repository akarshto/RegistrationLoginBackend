package com.example.registrationlogin.repository;

import com.example.registrationlogin.entity.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JwtTokenRepository extends JpaRepository<JwtToken, Long> {

    Optional<JwtToken> findByToken(String token);

    void deleteByToken(String token);
}
