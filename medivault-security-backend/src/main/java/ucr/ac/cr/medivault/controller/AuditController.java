package ucr.ac.cr.medivault.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ucr.ac.cr.medivault.business.SecurityAuditorService;
import ucr.ac.cr.medivault.controller.dto.AuditLogResponseDto;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auditoria")
public class AuditController {

    private final SecurityAuditorService auditor;

    public AuditController(SecurityAuditorService auditor) {
        this.auditor = auditor;
    }

    @GetMapping
    public ResponseEntity<List<AuditLogResponseDto>> ultimosEventos() {
        return ResponseEntity.ok(auditor.ultimosEventos());
    }
}
