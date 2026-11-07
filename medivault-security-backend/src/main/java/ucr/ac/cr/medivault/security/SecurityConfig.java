package ucr.ac.cr.medivault.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String BASE_URI = "https://medivault.ucr.ac.cr/";

    private final JwtAuthenticationFilter jwtFilter;
    private final RateLimitingFilter rateFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter, RateLimitingFilter rateFilter) {
        this.jwtFilter = jwtFilter;
        this.rateFilter = rateFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(JwtAuthenticationFilter f) {
        FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>(f);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateFilterRegistration(RateLimitingFilter f) {
        FilterRegistrationBean<RateLimitingFilter> reg = new FilterRegistrationBean<>(f);
        reg.setEnabled(false);
        return reg;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                .requestMatchers("/h2-console/**").denyAll()
                .requestMatchers("/api/v1/auditoria/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/api/v1/expedientes/**").authenticated()
                .anyRequest().authenticated()
            )
            .exceptionHandling(e -> e
                .authenticationEntryPoint((req, res, ex) -> ProblemJsonWriter.write(
                        res, 401, BASE_URI + "unauthorized", "No Autenticado",
                        "Autenticacion requerida.", req.getRequestURI()))
                .accessDeniedHandler((req, res, ex) -> ProblemJsonWriter.write(
                        res, 403, BASE_URI + "forbidden", "Acceso Prohibido",
                        "Acceso denegado.", req.getRequestURI()))
            )
            .headers(h -> h
                .frameOptions(f -> f.deny())
                .contentTypeOptions(Customizer.withDefaults())
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; "
                        + "base-uri 'none'; form-action 'self'"))
                .httpStrictTransportSecurity(hsts -> hsts
                        .requestMatcher(AnyRequestMatcher.INSTANCE)
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                .cacheControl(Customizer.withDefaults())
            )
            .addFilterBefore(rateFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
