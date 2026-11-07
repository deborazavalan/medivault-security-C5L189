package ucr.ac.cr.medivault.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ProblemJsonWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ProblemJsonWriter() {}

    public static void write(HttpServletResponse response, int status, String type,
                             String title, String detail, String instance) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", type);
        body.put("title", title);
        body.put("status", status);
        body.put("detail", detail);
        body.put("instance", instance);

        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }
}
