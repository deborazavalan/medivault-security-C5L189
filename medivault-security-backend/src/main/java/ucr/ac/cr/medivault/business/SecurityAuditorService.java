package ucr.ac.cr.medivault.business;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import ucr.ac.cr.medivault.controller.dto.AuditLogResponseDto;
import ucr.ac.cr.medivault.data.AuditLogRepository;
import ucr.ac.cr.medivault.domain.AuditLog;

import java.util.List;

@Service
public class SecurityAuditorService {

    public static final String IDOR_ATTEMPT_BLOCKED = "IDOR_ATTEMPT_BLOCKED";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";

    private static final Logger log = LoggerFactory.getLogger(SecurityAuditorService.class);

    private final AuditLogRepository repo;

    public SecurityAuditorService(AuditLogRepository repo) {
        this.repo = repo;
    }

    @Async("auditExecutor")
    public void registrarIdorBloqueado(String username, String ip, String recurso, Long expedienteId) {
        String detalle = expedienteId != null
                ? "Intento de acceso no autorizado al expediente " + expedienteId
                : "Intento de acceso no autorizado a un recurso protegido";
        guardar(username, ip, IDOR_ATTEMPT_BLOCKED, recurso, 403, detalle);
    }

    @Async("auditExecutor")
    public void registrarLoginFallido(String username, String ip, String recurso) {
        guardar(username, ip, LOGIN_FAILED, recurso, 401, "Credenciales invalidas");
    }

    public List<AuditLogResponseDto> ultimosEventos() {
        return repo.findTop50ByOrderByIdDesc().stream()
                .map(a -> new AuditLogResponseDto(
                        a.getId(), a.getUsername(), a.getIpOrigen(), a.getAccion(),
                        a.getRecursoSolicitado(), a.getCodigoEstado(),
                        a.getDetalleEvento(), a.getFechaEvento()))
                .toList();
    }

    private void guardar(String username, String ip, String accion,
                         String recurso, int codigo, String detalle) {
        try {
            repo.save(new AuditLog(
                    truncar(username, 50),
                    truncar(ip, 45),
                    truncar(accion, 50),
                    truncar(recurso, 255),
                    codigo,
                    truncar(detalle, 255)));
        } catch (Exception e) {
            log.error("No se pudo registrar el evento de auditoria {}", accion, e);
        }
    }

    private static String truncar(String valor, int max) {
        if (valor == null) {
            return null;
        }
        return valor.length() <= max ? valor : valor.substring(0, max);
    }
}
