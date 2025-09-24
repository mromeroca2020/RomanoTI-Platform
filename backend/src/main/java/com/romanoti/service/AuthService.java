package com.romanoti.service;

import com.romanoti.dto.LoginRequest;
import com.romanoti.dto.RegisterRequest;
import com.romanoti.model.User;
import com.romanoti.model.UserRole;
import com.romanoti.repository.UserRepository;
import com.romanoti.security.JwtService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    /**
     * Autenticar usuario y generar token JWT
     */
    public Optional<String> authenticate(LoginRequest loginRequest) {
        return userRepository.findByEmail(loginRequest.getEmail())
                .filter(user -> passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash()))
                .filter(User::getIsActive)
                .map(user -> jwtService.generateToken(user.getEmail(), user.getRole().name()));
    }

    /**
     * Autenticar usuario (sobrecarga con parámetros simples)
     */
    public Optional<String> authenticate(String email, String password) {
        return userRepository.findByEmail(email)
                .filter(user -> passwordEncoder.matches(password, user.getPasswordHash()))
                .filter(User::getIsActive)
                .map(user -> jwtService.generateToken(user.getEmail(), user.getRole().name()));
    }

    /**
     * Registrar nuevo usuario
     */
    public Optional<User> register(RegisterRequest registerRequest) {
        // Verificar si el email ya existe
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return Optional.empty();
        }

        // Crear nuevo usuario
        User newUser = new User();
        newUser.setEmail(registerRequest.getEmail());
        newUser.setPasswordHash(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setFirstName(registerRequest.getFirstName());
        newUser.setLastName(registerRequest.getLastName());
        newUser.setRole(registerRequest.getRole() != null ? registerRequest.getRole() : UserRole.CLIENT);
        newUser.setIsActive(true);

        User savedUser = userRepository.save(newUser);
        return Optional.of(savedUser);
    }

    /**
     * Registrar usuario con rol específico
     */
    public Optional<User> registerWithRole(RegisterRequest registerRequest, UserRole role) {
        registerRequest.setRole(role);
        return register(registerRequest);
    }

    /**
     * Validar token JWT
     */
    public boolean validateToken(String token) {
        return jwtService.validateToken(token);
    }

    /**
     * Obtener usuario desde token
     */
    public Optional<User> getUserFromToken(String token) {
        try {
            String email = jwtService.extractEmail(token);
            return userRepository.findByEmail(email);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Cambiar contraseña de usuario
     */
    public boolean changePassword(String email, String currentPassword, String newPassword) {
        return userRepository.findByEmail(email)
                .filter(user -> passwordEncoder.matches(currentPassword, user.getPasswordHash()))
                .map(user -> {
                    user.setPasswordHash(passwordEncoder.encode(newPassword));
                    userRepository.save(user);
                    return true;
                })
                .orElse(false);
    }

    /**
     * Activar/desactivar usuario
     */
    public boolean toggleUserStatus(String email, boolean isActive) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    user.setIsActive(isActive);
                    userRepository.save(user);
                    return true;
                })
                .orElse(false);
    }

    /**
     * Verificar si el email está disponible
     */
    public boolean isEmailAvailable(String email) {
        return !userRepository.existsByEmail(email);
    }

    /**
     * Generar token para usuario existente (útil para pruebas)
     */
    public Optional<String> generateTokenForUser(String email) {
        return userRepository.findByEmail(email)
                .filter(User::getIsActive)
                .map(user -> jwtService.generateToken(user.getEmail(), user.getRole().name()));
    }
}
