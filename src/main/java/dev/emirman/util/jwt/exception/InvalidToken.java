package dev.emirman.util.jwt.exception;

public class InvalidToken extends IllegalAccessError {
    public InvalidToken() {
        super("Invalid token");
    }
}
