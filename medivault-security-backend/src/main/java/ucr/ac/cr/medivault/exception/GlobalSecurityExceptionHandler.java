package ucr.ac.cr.medivault.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.security.ClientIpResolver;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalSecurityExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalSecurityExceptionHandler.class);

    private final SecurityAuditorService auditor;

    public GlobalSecurityExceptionHandler(SecurityAuditorService auditor) {
        this.auditor = auditor;
    }

    @ExceptionHandler(AccessDeniedSecurityException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedSecurityException ex,
                                            HttpServletRequest request) {
        auditor.registrarIdorBloqueado(
                usuarioActual(),
                ClientIpResolver.resolve(request),
                request.getRequestURI(),
                ex.getExpedienteId());

        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        p.setTitle("Acceso Prohibido (IDOR / BOLA)");
        p.setType(URI.create("https://medivault.ucr.ac.cr/forbidden"));
        return p;
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ProblemDetail handleSpringAccessDenied(
            org.springframework.security.access.AccessDeniedException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Acceso denegado.");
        p.setTitle("Acceso Prohibido");
        p.setType(URI.create("https://medivault.ucr.ac.cr/forbidden"));
        return p;
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ProblemDetail handleNotFound(ResourceNotFoundException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        p.setTitle("Recurso No Encontrado");
        p.setType(URI.create("https://medivault.ucr.ac.cr/not-found"));
        return p;
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex,
                                              HttpServletRequest request) {
        String intento = ex instanceof LoginFailedException lf ? lf.getAttemptedUsername() : null;
        auditor.registrarLoginFallido(intento, ClientIpResolver.resolve(request), request.getRequestURI());

        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Credenciales invalidas.");
        p.setTitle("Fallo de Autenticacion");
        p.setType(URI.create("https://medivault.ucr.ac.cr/unauthorized"));
        return p;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Solicitud invalida.");
        p.setTitle("Error de Validacion");
        p.setType(URI.create("https://medivault.ucr.ac.cr/bad-request"));
        return p;
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleIntegrity(DataIntegrityViolationException ex,
                                         HttpServletRequest request) {
        log.warn("Violacion de integridad en {}", request.getRequestURI());
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
                "El registro entra en conflicto con datos existentes.");
        p.setTitle("Conflicto de Datos");
        p.setType(URI.create("https://medivault.ucr.ac.cr/conflict"));
        return p;
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {

        ProblemDetail p = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Validacion de datos fallida.");
        p.setTitle("Error de Validacion");
        p.setType(URI.create("https://medivault.ucr.ac.cr/bad-request"));

        Map<String, String> errors = new LinkedHashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            errors.putIfAbsent(fe.getField(), fe.getDefaultMessage());
        }
        p.setProperty("invalid_fields", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(p);
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGeneric(Exception ex, HttpServletRequest request) {
        log.error("Error no controlado en {}", request.getRequestURI(), ex);
        ProblemDetail p = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "Error interno del servidor.");
        p.setTitle("Error Interno");
        p.setType(URI.create("https://medivault.ucr.ac.cr/internal"));
        return p;
    }

    private String usuarioActual() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : null;
    }
}
