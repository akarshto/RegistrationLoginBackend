package com.example.registrationlogin.security;

import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.service.AuthenticationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 * Reads the JWT solely from the HttpOnly cookie (never from a header or
 * localStorage/sessionStorage) and, if valid, populates the SecurityContext
 * so downstream controllers see an authenticated user.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthenticationService authenticationService;
    private final String cookieName;

    public JwtAuthFilter(AuthenticationService authenticationService,
            @Value("${app.jwt.cookie-name}") String cookieName) {
        this.authenticationService = authenticationService;
        this.cookieName = cookieName;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String token = extractTokenFromCookie(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                User user = authenticationService.validateSessionAndGetUser(token);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        user.getUsername(), null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authToken);
                request.setAttribute("jwtToken", token);
            } catch (RuntimeException ex) {
                // Invalid/expired token: leave context unauthenticated; protected
                // endpoints will reject the request with 401 via Spring Security.
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
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
