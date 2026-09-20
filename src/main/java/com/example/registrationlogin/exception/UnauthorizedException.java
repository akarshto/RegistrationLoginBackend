package com.example.registrationlogin.exception;

/** Thrown when a request is missing a valid JWT (expired, tampered, or absent). */
public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(String message) {
        super(message);
    }
}
