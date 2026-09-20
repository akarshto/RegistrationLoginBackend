package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.LoginRequest;
import com.example.registrationlogin.entity.JwtToken;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.exception.InvalidCredentialsException;
import com.example.registrationlogin.exception.UnauthorizedException;
import com.example.registrationlogin.repository.JwtTokenRepository;
import com.example.registrationlogin.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Authentication Service — owns login, session validation, and logout.
 * Passwords are never decrypted; login compares the raw entered password
 * against the stored BCrypt hash via PasswordEncoder.matches().
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final JwtTokenRepository jwtTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationService(UserRepository userRepository,
            JwtTokenRepository jwtTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtTokenRepository = jwtTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    @NonNull
    public String login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        // entered password -> BCryptPasswordEncoder.matches() -> stored BCrypt password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        String token = jwtService.generateToken(user.getUsername(), user.getUserId());

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiry = now.plusNanos(jwtService.getExpirationMs() * 1_000_000);

        JwtToken tokenRecord = new JwtToken(user.getUserId(), token, now, expiry);
        jwtTokenRepository.save(tokenRecord);

        return token;
    }

    /**
     * Validates a cookie's JWT against signature/expiry AND the DB allow-list, then
     * returns the user.
     */
    public User validateSessionAndGetUser(String token) {
        if (token == null || token.isBlank()) {
            throw new UnauthorizedException("Not authenticated");
        }
        if (!jwtService.isTokenValid(token)) {
            throw new UnauthorizedException("Session expired, please log in again");
        }

        JwtToken tokenRecord = jwtTokenRepository.findByToken(token)
                .orElseThrow(() -> new UnauthorizedException("Session not recognized, please log in again"));

        if (tokenRecord.getExpiredAt().isBefore(LocalDateTime.now())) {
            jwtTokenRepository.deleteByToken(token);
            throw new UnauthorizedException("Session expired, please log in again");
        }

        String username = jwtService.extractUsername(token);
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UnauthorizedException("User no longer exists"));
    }

    @Transactional
    public void logout(String token) {
        if (token != null && !token.isBlank()) {
            jwtTokenRepository.deleteByToken(token);
        }
    }
}
