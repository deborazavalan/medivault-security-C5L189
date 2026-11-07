package ucr.ac.cr.medivault.business;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ucr.ac.cr.medivault.controller.dto.LoginRequestDto;
import ucr.ac.cr.medivault.controller.dto.LoginResponseDto;
import ucr.ac.cr.medivault.data.UsuarioRepository;
import ucr.ac.cr.medivault.domain.Usuario;
import ucr.ac.cr.medivault.exception.LoginFailedException;
import ucr.ac.cr.medivault.security.JwtTokenProvider;

@Service
public class AuthService {

    private final UsuarioRepository userRepo;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwtProvider;
    private final String dummyHash;

    public AuthService(UsuarioRepository userRepo,
                       PasswordEncoder encoder,
                       JwtTokenProvider jwtProvider) {
        this.userRepo = userRepo;
        this.encoder = encoder;
        this.jwtProvider = jwtProvider;
        this.dummyHash = encoder.encode("dummy-password-for-timing");
    }

    @Transactional(readOnly = true)
    public LoginResponseDto autenticar(LoginRequestDto request) {
        Usuario u = userRepo.findByUsername(request.username()).orElse(null);

        if (u == null) {
            encoder.matches(request.password(), dummyHash);
            throw new LoginFailedException(request.username());
        }
        if (!encoder.matches(request.password(), u.getPasswordHash())) {
            throw new LoginFailedException(request.username());
        }
        if (!"ACTIVO".equals(u.getEstado())) {
            throw new LoginFailedException(request.username());
        }

        String token = jwtProvider.generateToken(u.getUsername(), u.getRol().name());

        return new LoginResponseDto(
                token,
                "Bearer",
                jwtProvider.getExpirationMs(),
                u.getUsername(),
                u.getRol().name());
    }
}
