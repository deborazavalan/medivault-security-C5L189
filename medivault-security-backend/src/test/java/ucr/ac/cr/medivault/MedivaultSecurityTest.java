package ucr.ac.cr.medivault;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import ucr.ac.cr.medivault.data.AuditLogRepository;
import ucr.ac.cr.medivault.security.JwtTokenProvider;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MedivaultSecurityTest {

    @Autowired MockMvc mvc;
    @Autowired JwtTokenProvider jwt;
    @Autowired AuditLogRepository audit;

    private static RequestPostProcessor from(String ip) {
        return r -> { r.setRemoteAddr(ip); return r; };
    }

    private String bearer(String user, String role) {
        return "Bearer " + jwt.generateToken(user, role);
    }

    private static String loginJson(String user, String pass) {
        return "{\"username\":\"" + user + "\",\"password\":\"" + pass + "\"}";
    }

    @Test
    void loginExitosoDevuelveToken() throws Exception {
        mvc.perform(post("/api/v1/auth/login").with(from("10.1.0.1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("paciente_carlos", "Password123!")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.rol").value("ROLE_PACIENTE"));
    }

    @Test
    void loginFallidoDevuelve401YSeAudita() throws Exception {
        long antes = audit.countByAccion("LOGIN_FAILED");

        mvc.perform(post("/api/v1/auth/login").with(from("10.1.0.2"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("paciente_carlos", "ClaveIncorrecta1")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Fallo de Autenticacion"));

        await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(audit.countByAccion("LOGIN_FAILED")).isGreaterThan(antes));
    }

    @Test
    void cabecerasDefensivasPresentes() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.3"))
                        .header("Authorization", bearer("paciente_carlos", "ROLE_PACIENTE")))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Strict-Transport-Security", containsString("max-age=31536000")))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void pacienteConsultaSuExpediente() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.4"))
                        .header("Authorization", bearer("paciente_carlos", "ROLE_PACIENTE")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.codigoExpediente").value("EXP-2026-001"))
                .andExpect(jsonPath("$.fechaRegistro").isNotEmpty());
    }

    @Test
    void idorBloqueadoYAuditado() throws Exception {
        long antes = audit.countByAccion("IDOR_ATTEMPT_BLOCKED");

        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.5"))
                        .header("Authorization", bearer("paciente_maria", "ROLE_PACIENTE")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://medivault.ucr.ac.cr/forbidden"))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.detail").value("Violacion IDOR: Acceso no autorizado."));

        await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(audit.countByAccion("IDOR_ATTEMPT_BLOCKED")).isGreaterThan(antes));

        var ultimo = audit.findTop50ByOrderByIdDesc().stream()
                .filter(a -> "IDOR_ATTEMPT_BLOCKED".equals(a.getAccion()))
                .findFirst().orElseThrow();
        assertThat(ultimo.getUsername()).isEqualTo("paciente_maria");
        assertThat(ultimo.getIpOrigen()).isEqualTo("10.1.0.5");
        assertThat(ultimo.getCodigoEstado()).isEqualTo(403);
        assertThat(ultimo.getDetalleEvento()).contains("101");
    }

    @Test
    void doctorNoAsignadoRecibe403() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.6"))
                        .header("Authorization", bearer("doctora_vargas", "ROLE_DOCTOR")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value("Violacion BOLA: No asignado."));
    }

    @Test
    void adminPuedeAuditarYExpedienteInexistenteDa404() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.7"))
                        .header("Authorization", bearer("admin_root", "ROLE_ADMIN")))
                .andExpect(status().isOk());

        mvc.perform(get("/api/v1/expedientes/9999").with(from("10.1.0.7"))
                        .header("Authorization", bearer("admin_root", "ROLE_ADMIN")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Recurso No Encontrado"));
    }

    @Test
    void sinTokenDevuelve401() throws Exception {
        mvc.perform(get("/api/v1/expedientes/101").with(from("10.1.0.8")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void validacionDevuelve400SinFugas() throws Exception {
        mvc.perform(post("/api/v1/auth/login").with(from("10.1.0.9"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("a", "corta")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.invalid_fields.username").exists())
                .andExpect(jsonPath("$.invalid_fields.password").exists());
    }

    @Test
    void rateLimitPorIpBloqueaLaSextaPeticion() throws Exception {
        for (int i = 1; i <= 5; i++) {
            mvc.perform(post("/api/v1/auth/login").with(from("10.2.0.1"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson("admin_root", "ClaveErronea1")))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login").with(from("10.2.0.1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("admin_root", "ClaveErronea1")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    void bucketsSonIndependientesPorIpDeXForwardedFor() throws Exception {
        for (int i = 1; i <= 5; i++) {
            mvc.perform(post("/api/v1/auth/login").with(from("10.3.0.1"))
                    .header("X-Forwarded-For", "203.0.113.5, 10.3.0.1")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(loginJson("admin_root", "ClaveErronea1")));
        }
        mvc.perform(post("/api/v1/auth/login").with(from("10.3.0.1"))
                        .header("X-Forwarded-For", "203.0.113.5")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("admin_root", "ClaveErronea1")))
                .andExpect(status().isTooManyRequests());

        mvc.perform(post("/api/v1/auth/login").with(from("10.3.0.1"))
                        .header("X-Forwarded-For", "203.0.113.6")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("admin_root", "ClaveErronea1")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void soloElMedicoAsignadoActualizaNotas() throws Exception {
        String body = "{\"notasClinicas\":\"Control en 15 dias con laboratorio.\"}";

        mvc.perform(patch("/api/v1/expedientes/101/notas").with(from("10.4.0.1"))
                        .header("Authorization", bearer("paciente_carlos", "ROLE_PACIENTE"))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        mvc.perform(patch("/api/v1/expedientes/101/notas").with(from("10.4.0.1"))
                        .header("Authorization", bearer("doctora_vargas", "ROLE_DOCTOR"))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());

        mvc.perform(patch("/api/v1/expedientes/101/notas").with(from("10.4.0.1"))
                        .header("Authorization", bearer("doctor_smith", "ROLE_DOCTOR"))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());
    }

    @Test
    void soloAdminConsultaLaAuditoria() throws Exception {
        mvc.perform(get("/api/v1/auditoria").with(from("10.5.0.1"))
                        .header("Authorization", bearer("paciente_carlos", "ROLE_PACIENTE")))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/v1/auditoria").with(from("10.5.0.1"))
                        .header("Authorization", bearer("admin_root", "ROLE_ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].accion").exists());
    }
}
