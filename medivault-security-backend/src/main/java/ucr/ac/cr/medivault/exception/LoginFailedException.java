package ucr.ac.cr.medivault.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class LoginFailedException extends BadCredentialsException {

    private final String attemptedUsername;

    public LoginFailedException(String attemptedUsername) {
        super("Credenciales invalidas.");
        this.attemptedUsername = attemptedUsername;
    }

    public String getAttemptedUsername() {
        return attemptedUsername;
    }
}
