package com.example.registrationlogin.config;

import com.example.registrationlogin.security.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    /*
     * This value comes from application.properties/application.yml
     * or from the Render environment variable:
     *
     * APP_CORS_ALLOWED_ORIGIN
     *
     * Example:
     * https://your-project.vercel.app
     *
     * The localhost default keeps your local development working.
     */
    @Value("${app.cors.allowed-origin:http://localhost:3000}")
    private String allowedOrigin;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // Disable CSRF because this is a stateless JWT API.
                .csrf(csrf -> csrf.disable())

                // Enable CORS.
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Do not create server-side sessions.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // API authorization rules.
                .authorizeHttpRequests(auth -> auth

                        // Anyone can register.
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/registration")
                        .permitAll()

                        // Anyone can login.
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/login")
                        .permitAll()

                        // Anyone can logout.
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/logout")
                        .permitAll()

                        // User information requires JWT authentication.
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/user/me")
                        .authenticated()

                        // Everything else requires authentication.
                        .anyRequest().authenticated())

                // Run JWT authentication before Spring's
                // UsernamePasswordAuthenticationFilter.
                .addFilterBefore(
                        jwtAuthFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CORS configuration for the React/Vercel frontend.
     *
     * Credentials are enabled because your application
     * uses an HttpOnly JWT cookie.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        /*
         * Supports one or multiple origins.
         *
         * For example, Render can receive:
         *
         * APP_CORS_ALLOWED_ORIGIN=
         * https://your-project.vercel.app,http://localhost:3000
         */
        List<String> origins = Arrays.stream(
                allowedOrigin.split(","))
                .map(origin -> origin.trim())
                .filter(origin -> !origin.isEmpty())
                .toList();

        configuration.setAllowedOrigins(origins);

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "OPTIONS"));

        configuration.setAllowedHeaders(
                List.of("*"));

        /*
         * REQUIRED for your JWT cookie.
         */
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
                "/**",
                configuration);

        return source;
    }
}