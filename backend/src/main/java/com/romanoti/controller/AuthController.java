package com.romanoti.controller;

import com.romanoti.dto.AuthResponse;
import com.romanoti.dto.LoginRequest;
import com.romanoti.dto.RegisterRequest;
import com.romanoti.model.User;
import com.romanoti.service.AuthService;
import com.romanoti.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    /**
     * Endpoint para login de usuarios
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Optional<String> token = authService.authenticate(loginRequest);
            
            if (token.isPresent()) {
                // Obtener información del usuario para la respuesta
                Optional<User> user = userService.findByEmail(loginRequest.getEmail());
                
                if (user.isPresent()) {
                    AuthResponse response = new AuthResponse(
                        token.get(),
                        user.get().getId(),
                        user.get().getEmail(),
                        user.get().getRole().name(),
                        user.get().getFirstName(),
                        user.get().getLastName()
                    );
                    return ResponseEntity.ok(response);
                }
            }
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Error: Credenciales inválidas o usuario inactivo");
                    
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error interno del servidor: " + e.getMessage());
        }
    }

    /**
     * Endpoint para registro de nuevos usuarios
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            // Verificar si el email ya está registrado
            if (!authService.isEmailAvailable(registerRequest.getEmail())) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body("Error: El email ya está registrado");
            }

            Optional<User> newUser = authService.register(registerRequest);
            
            if (newUser.isPresent()) {
                // Generar token para el nuevo usuario
                Optional<String> token = authService.generateTokenForUser(registerRequest.getEmail());
                
                if (token.isPresent()) {
                    User user = newUser.get();
                    AuthResponse response = new AuthResponse(
                        token.get(),
                        user.getId(),
                        user.getEmail(),
                        user.getRole().name(),
                        user.getFirstName(),
                        user.getLastName()
                    );
                    
                    return ResponseEntity.status(HttpStatus.CREATED).body(response);
                }
            }
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error: No se pudo registrar el usuario");
                    
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error interno del servidor: " + e.getMessage());
        }
    }

    /**
     * Endpoint para validar token JWT
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Error: Token no proporcionado o formato inválido");
            }

            String token = authHeader.substring(7);
            boolean isValid = authService.validateToken(token);

            if (isValid) {
                Optional<User> user = authService.getUserFromToken(token);
                if (user.isPresent()) {
                    return ResponseEntity.ok("Token válido para el usuario: " + user.get().getEmail());
                }
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Error: Token inválido o expirado");
                    
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error interno del servidor: " + e.getMessage());
        }
    }

    /**
     * Endpoint para obtener información del usuario actual
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Error: Token no proporcionado");
            }

            String token = authHeader.substring(7);
            Optional<User> user = authService.getUserFromToken(token);

            if (user.isPresent() && user.get().getIsActive()) {
                // Crear respuesta sin información sensible
                AuthResponse response = new AuthResponse();
                response.setId(user.get().getId());
                response.setEmail(user.get().getEmail());
                response.setRole(user.get().getRole().name());
                response.setFirstName(user.get().getFirstName());
                response.setLastName(user.get().getLastName());
                response.setFullName(user.get().getFullName());
                
                return ResponseEntity.ok(response);
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Error: Usuario no encontrado o inactivo");
                    
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error interno del servidor: " + e.getMessage());
        }
    }

    /**
     * Endpoint de verificación de salud del servicio de autenticación
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("Servicio de autenticación funcionando correctamente");
    }
}
