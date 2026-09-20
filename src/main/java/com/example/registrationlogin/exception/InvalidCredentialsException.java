package com.example.registrationlogin.exception;

/** Thrown on login when username/password do not match. Kept generic to avoid user enumeration. */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}
