package ucr.ac.cr.medivault.security;

import jakarta.servlet.http.HttpServletRequest;

public final class ClientIpResolver {

    private static final String XFF = "X-Forwarded-For";

    private ClientIpResolver() {}

    public static String resolve(HttpServletRequest request) {
        String forwarded = request.getHeader(XFF);
        if (forwarded != null && !forwarded.isBlank()) {
            String first = forwarded.split(",")[0].trim();
            if (esIpPlausible(first)) {
                return first;
            }
        }
        return request.getRemoteAddr();
    }

    private static boolean esIpPlausible(String ip) {
        return !ip.isEmpty() && ip.length() <= 45 && ip.matches("[0-9a-fA-F:.]+");
    }
}
