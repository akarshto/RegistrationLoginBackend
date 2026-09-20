package com.example.registrationlogin.controller;

import com.example.registrationlogin.dto.LoginRequest;
import com.example.registrationlogin.dto.MessageResponse;
import com.example.registrationlogin.dto.UserResponse;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.exception.UnauthorizedException;
import com.example.registrationlogin.service.AuthenticationService;
import com.example.registrationlogin.service.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    @NonNull
    private final String cookieName;

    public AuthController(AuthenticationService authenticationService, JwtService jwtService,
            @Value("${app.jwt.cookie-name}") @NonNull String cookieName) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
        this.cookieName = cookieName;
    }

    @PostMapping("/login")
    public ResponseEntity<MessageResponse> login(@Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        String token = authenticationService.login(request);

        ResponseCookie cookie = ResponseCookie.from(cookieName, token)
                .httpOnly(true)
                .secure(false) // set true when serving over HTTPS in production
                .path("/")
                .maxAge(jwtService.getExpirationMs() / 1000) // 1 hour
                .sameSite("Lax")
                .build();

        response.addHeader("Set-Cookie", cookie.toString());
        return ResponseEntity.ok(new MessageResponse("Login successful"));
    }

    @GetMapping("/user/me")
    public ResponseEntity<UserResponse> me(HttpServletRequest request) {
        String token = extractCookie(request);
        if (token == null) {
            throw new UnauthorizedException("Not authenticated");
        }
        User user = authenticationService.validateSessionAndGetUser(token);
        return ResponseEntity.ok(new UserResponse(user.getUsername(), user.getEmail()));
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        String token = extractCookie(request);
        authenticationService.logout(token);

        ResponseCookie expiredCookie = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .sameSite("Lax")
                .build();

        response.addHeader("Set-Cookie", expiredCookie.toString());
        return ResponseEntity.ok(new MessageResponse("Logged out"));
    }

    private String extractCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
