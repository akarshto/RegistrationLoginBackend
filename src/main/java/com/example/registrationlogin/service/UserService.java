package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.SignupRequest;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.exception.DuplicateResourceException;
import com.example.registrationlogin.exception.PasswordMismatchException;
import com.example.registrationlogin.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User Service — owns registration and user lookups.
 * The raw password/confirmPassword never leave this class; only the BCrypt
 * hash produced by PasswordEncoder is persisted.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User register(SignupRequest request) {
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException("Password and confirm password do not match");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateResourceException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateResourceException("Email already exists");
        }

        // raw password -> BCryptPasswordEncoder -> encoded password -> MySQL
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        User user = new User(
                request.getUsername(),
                encodedPassword,
                request.getEmail(),
                request.getPhoneNumber());

        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
}
