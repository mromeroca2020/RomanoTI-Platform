package com.romanoti.repository;

import com.romanoti.model.User;
import com.romanoti.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    
    // Encontrar usuario por email
    Optional<User> findByEmail(String email);
    
    // Verificar si existe un usuario por email
    boolean existsByEmail(String email);
    
    // Encontrar usuarios por rol
    List<User> findByRole(UserRole role);
    
    // Encontrar usuarios activos
    List<User> findByIsActiveTrue();
    
    // Encontrar usuarios activos por rol
    List<User> findByRoleAndIsActiveTrue(UserRole role);
    
    // Búsqueda por nombre o apellido (case insensitive)
    @Query("SELECT u FROM User u WHERE LOWER(u.firstName) LIKE LOWER(CONCAT('%', :name, '%')) OR LOWER(u.lastName) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<User> findByFirstNameContainingOrLastNameContainingIgnoreCase(@Param("name") String name);
    
    // Contar usuarios por rol
    long countByRole(UserRole role);
    
    // Contar usuarios activos
    long countByIsActiveTrue();
    
    // Encontrar usuarios por múltiples roles
    @Query("SELECT u FROM User u WHERE u.role IN :roles")
    List<User> findByRoles(@Param("roles") List<UserRole> roles);
    
    // Verificar si existe un usuario activo por email
    boolean existsByEmailAndIsActiveTrue(String email);
}
