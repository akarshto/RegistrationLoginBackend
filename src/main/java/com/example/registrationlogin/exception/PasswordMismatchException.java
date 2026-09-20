package com.example.registrationlogin.exception;

/** Thrown when password and confirmPassword do not match. */
public class PasswordMismatchException extends RuntimeException {
    public PasswordMismatchException(String message) {
        super(message);
    }
}
