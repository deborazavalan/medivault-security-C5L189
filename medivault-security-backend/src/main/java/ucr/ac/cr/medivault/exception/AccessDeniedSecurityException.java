package ucr.ac.cr.medivault.exception;

public class AccessDeniedSecurityException extends RuntimeException {

    private final Long expedienteId;

    public AccessDeniedSecurityException(String msg) {
        this(msg, null);
    }

    public AccessDeniedSecurityException(String msg, Long expedienteId) {
        super(msg);
        this.expedienteId = expedienteId;
    }

    public Long getExpedienteId() {
        return expedienteId;
    }
}
