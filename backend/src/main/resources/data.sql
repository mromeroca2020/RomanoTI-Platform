-- =============================================
-- DATOS INICIALES PARA ROMANOTI PLATFORM
-- =============================================

-- Insertar usuarios iniciales (contraseñas: 'password123')
INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at) 
VALUES 
    (
        '11111111-1111-1111-1111-111111111111', 
        'admin@romanoti.com', 
        '$2a$10$8S5/6RzBzHkK8JkY8JkY8eK8JkY8JkY8JkY8JkY8JkY8JkY8JkY8J', 
        'Admin', 
        'Sistema', 
        'ADMIN', 
        true, 
        CURRENT_TIMESTAMP, 
        CURRENT_TIMESTAMP
    ),
    (
        '22222222-2222-2222-2222-222222222222', 
        'empleado@romanoti.com', 
        '$2a$10$8S5/6RzBzHkK8JkY8JkY8eK8JkY8JkY8JkY8JkY8JkY8JkY8JkY8J', 
        'María', 
        'Gonzalez', 
        'EMPLOYEE', 
        true, 
        CURRENT_TIMESTAMP, 
        CURRENT_TIMESTAMP
    ),
    (
        '33333333-3333-3333-3333-333333333333', 
        'cliente@ejemplo.com', 
        '$2a$10$8S5/6RzBzHkK8JkY8JkY8eK8JkY8JkY8JkY8JkY8JkY8JkY8JkY8J', 
        'Carlos', 
        'López', 
        'CLIENT', 
        true, 
        CURRENT_TIMESTAMP, 
        CURRENT_TIMESTAMP
    ),
    (
        '44444444-4444-4444-4444-444444444444', 
        'juan.perez@empresa.com', 
        '$2a$10$8S5/6RzBzHkK8JkY8JkY8eK8JkY8JkY8JkY8JkY8JkY8JkY8JkY8J', 
        'Juan', 
        'Pérez', 
        'CLIENT', 
        true, 
        CURRENT_TIMESTAMP, 
        CURRENT_TIMESTAMP
    );

-- Insertar clientes/empresas iniciales
INSERT INTO clients (id, company_name, contact_email, phone, address, sector, status, assigned_employee_id, created_at) 
VALUES 
    (
        '55555555-5555-5555-5555-555555555555',
        'TechSolutions SA',
        'cliente@ejemplo.com',
        '+57 300 123 4567',
        'Calle 123 #45-67, Bogotá',
        'Tecnología',
        'active',
        '22222222-2222-2222-2222-222222222222',
        CURRENT_TIMESTAMP
    ),
    (
        '66666666-6666-6666-6666-666666666666',
        'Innovatech Colombia',
        'juan.perez@empresa.com',
        '+57 310 987 6543',
        'Av. Principal #89-10, Medellín',
        'Consultoría IT',
        'active',
        '22222222-2222-2222-2222-222222222222',
        CURRENT_TIMESTAMP
    );

-- Insertar proyectos de ejemplo
INSERT INTO projects (id, name, description, client_id, status, start_date, end_date, budget, created_by, created_at) 
VALUES 
    (
        '77777777-7777-7777-7777-777777777777',
        'Migración a la Nube',
        'Migración completa de infraestructura a AWS',
        '55555555-5555-5555-5555-555555555555',
        'in_progress',
        '2024-01-15',
        '2024-06-30',
        50000.00,
        '22222222-2222-2222-2222-222222222222',
        CURRENT_TIMESTAMP
    ),
    (
        '88888888-8888-8888-8888-888888888888',
        'Desarrollo App Móvil',
        'Aplicación móvil para gestión de inventarios',
        '66666666-6666-6666-6666-666666666666',
        'planning',
        '2024-02-01',
        '2024-08-31',
        35000.00,
        '22222222-2222-2222-2222-222222222222',
        CURRENT_TIMESTAMP
    );

-- Insertar tickets de soporte de ejemplo
INSERT INTO tickets (id, title, description, client_id, created_by, assigned_to, priority, status, created_at, updated_at) 
VALUES 
    (
        '99999999-9999-9999-9999-999999999999',
        'Error en login',
        'No puedo iniciar sesión en la plataforma',
        '55555555-5555-5555-5555-555555555555',
        '33333333-3333-3333-3333-333333333333',
        '22222222-2222-2222-2222-222222222222',
        'high',
        'open',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    );
