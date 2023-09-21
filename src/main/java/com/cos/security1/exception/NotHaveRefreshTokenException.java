package com.cos.security1.exception;

public class NotHaveRefreshTokenException extends NullPointerException{

    public NotHaveRefreshTokenException(String message) {
        super(message);
    }
}
