package com.example.registrationlogin.exception;

/** Thrown when a username or email already exists at registration time. */
public class DuplicateResourceException extends RuntimeException {
    public DuplicateResourceException(String message) {
        super(message);
    }
}
