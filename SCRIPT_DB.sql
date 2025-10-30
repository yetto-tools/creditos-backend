-- alter session set "_ORACLE_SCRIPT"=true;
-- create user  usr_app identified by temporal_123;
-- grant all privileges to usr_app;


-- ============================================================================
-- PROYECTO FINAL - PROGRAMACIÓN 2
-- SISTEMA DE OPERACIONES FINANCIERAS BANCARIAS
-- SCRIPT COMPLETO PARA CREAR LA BASE DE DATOS ORACLE
-- ============================================================================
-- Este script CREA:
-- 1. Tablespaces (espacios de almacenamiento)
-- 2. Usuario de base de datos
-- 3. Permisos y roles
-- 4. Todas las tablas
-- 5. Índices
-- 6. Vistas
-- 7. Procedimientos almacenados
-- ============================================================================

-- ============================================================================
-- PASO 1: CREAR TABLESPACES (ESPACIOS DE ALMACENAMIENTO)
-- ============================================================================

-- Para Oracle 21c Express, usaremos el tablespace por defecto XEPDB1
-- Si necesitas crear tablespaces específicos, descomenta lo siguiente:

/*
CREATE TABLESPACE TS_BANCO
  DATAFILE '/u01/oradata/TS_BANCO01.dbf' SIZE 500M
  AUTOEXTEND ON NEXT 100M MAXSIZE UNLIMITED
  EXTENT MANAGEMENT LOCAL AUTOALLOCATE
  SEGMENT SPACE MANAGEMENT AUTO;

CREATE TEMPORARY TABLESPACE TS_BANCO_TEMP
  TEMPFILE '/u01/oradata/TS_BANCO_TEMP01.dbf' SIZE 100M
  AUTOEXTEND ON NEXT 50M MAXSIZE UNLIMITED
  EXTENT MANAGEMENT LOCAL AUTOALLOCATE
  SEGMENT SPACE MANAGEMENT AUTO;
*/

-- ============================================================================
-- PASO 2: CREAR USUARIO DE BASE DE DATOS
-- ============================================================================

-- Primero, eliminar el usuario si existe
BEGIN
  BEGIN
    EXECUTE IMMEDIATE 'DROP USER banco_usr CASCADE';
  EXCEPTION
    WHEN OTHERS THEN NULL;
  END;
END;
/

-- Crear el usuario
CREATE USER banco_usr IDENTIFIED BY "BancoApp2025!"
DEFAULT TABLESPACE USERS
TEMPORARY TABLESPACE TEMP;

-- ============================================================================
-- PASO 3: OTORGAR PERMISOS AL USUARIO
-- ============================================================================

-- Permisos básicos
GRANT CONNECT TO banco_usr;
GRANT RESOURCE TO banco_usr;
GRANT CREATE SESSION TO banco_usr;
GRANT CREATE TABLE TO banco_usr;
GRANT CREATE INDEX TO banco_usr;
GRANT CREATE VIEW TO banco_usr;
GRANT CREATE PROCEDURE TO banco_usr;
GRANT CREATE SEQUENCE TO banco_usr;

-- Cuota de almacenamiento ilimitada
ALTER USER banco_usr QUOTA UNLIMITED ON USERS;
ALTER USER banco_usr QUOTA UNLIMITED ON TEMP;

-- ============================================================================
-- PASO 4: CONECTAR COMO USUARIO Y CREAR TABLAS
-- ============================================================================

-- Cambiar contexto al usuario banco_usr
CONNECT banco_usr/BancoApp2025!

-- ============================================================================
-- 4.1 TABLA DE USUARIOS - Gestión de acceso
-- ============================================================================

CREATE TABLE usuarios (
    id_usuario NUMBER(10) PRIMARY KEY,
    usuario VARCHAR2(50) NOT NULL UNIQUE,
    contrasena VARCHAR2(255) NOT NULL,
    nombre_completo VARCHAR2(100),
    correo_electronico VARCHAR2(100),
    estado VARCHAR2(20) DEFAULT 'ACTIVO' CHECK (estado IN ('ACTIVO', 'INACTIVO')),
    fecha_creacion DATE DEFAULT SYSDATE,
    fecha_ultimo_acceso DATE,
    fecha_cambio_contrasena DATE DEFAULT SYSDATE
);

-- Crear secuencia para usuarios
CREATE SEQUENCE seq_usuarios START WITH 1 INCREMENT BY 1;

-- Agregar comentarios a la tabla
COMMENT ON TABLE usuarios IS 'Tabla que almacena los usuarios del sistema para autenticación y autorización';
COMMENT ON COLUMN usuarios.id_usuario IS 'Identificador único del usuario';
COMMENT ON COLUMN usuarios.usuario IS 'Nombre de usuario para login';
COMMENT ON COLUMN usuarios.contrasena IS 'Contraseña encriptada del usuario';
COMMENT ON COLUMN usuarios.estado IS 'Estado del usuario: ACTIVO o INACTIVO';

-- ============================================================================
-- 4.2 TABLA DE MONEDAS - Catálogo de monedas
-- ============================================================================

CREATE TABLE monedas (
    id_moneda NUMBER(5) PRIMARY KEY,
    codigo_moneda VARCHAR2(3) NOT NULL UNIQUE,
    nombre_moneda VARCHAR2(50) NOT NULL,
    simbolo VARCHAR2(5),
    estado VARCHAR2(20) DEFAULT 'ACTIVO' CHECK (estado IN ('ACTIVO', 'INACTIVO'))
);

-- Agregar comentarios
COMMENT ON TABLE monedas IS 'Tabla que define las monedas con las que se pueden hacer operaciones';
COMMENT ON COLUMN monedas.codigo_moneda IS 'Código ISO de la moneda (GTQ, USD, EUR)';

-- ============================================================================
-- 4.3 TABLA DE INVERSIONES - Operaciones de entrada de capital
-- ============================================================================

CREATE TABLE inversiones (
    id_inversion NUMBER(15) PRIMARY KEY,
    id_usuario NUMBER(10) NOT NULL,
    id_moneda NUMBER(5) NOT NULL,
    capital_inicial NUMBER(15,2) NOT NULL,
    tasa_interes NUMBER(5,2) NOT NULL,
    plazo_dias NUMBER(5) NOT NULL,
    modalidad_pago VARCHAR2(20) NOT NULL CHECK (modalidad_pago IN ('MENSUAL', 'FINAL')),
    fecha_inicio DATE DEFAULT SYSDATE NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    interes_total_proyectado NUMBER(15,2),
    monto_total_a_recibir NUMBER(15,2),
    estado VARCHAR2(20) DEFAULT 'VIGENTE' CHECK (estado IN ('VIGENTE', 'VENCIDA', 'CANCELADA')),
    fecha_creacion DATE DEFAULT SYSDATE,
    observaciones VARCHAR2(500),
    CONSTRAINT fk_inv_usuario FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario),
    CONSTRAINT fk_inv_moneda FOREIGN KEY (id_moneda) REFERENCES monedas(id_moneda)
);

CREATE SEQUENCE seq_inversiones START WITH 1000 INCREMENT BY 1;

COMMENT ON TABLE inversiones IS 'Tabla que registra todas las inversiones de clientes en el sistema';
COMMENT ON COLUMN inversiones.modalidad_pago IS 'Forma de pago: MENSUAL (pagos mensuales) o FINAL (un solo pago al vencimiento)';
COMMENT ON COLUMN inversiones.estado IS 'VIGENTE (activa), VENCIDA (plazo terminó), CANCELADA (cancelada manualmente)';

-- ============================================================================
-- 4.4 TABLA DE PAGOS DE INVERSIONES - Detalles de pagos
-- ============================================================================

CREATE TABLE pagos_inversiones (
    id_pago_inversion NUMBER(15) PRIMARY KEY,
    id_inversion NUMBER(15) NOT NULL,
    numero_pago NUMBER(3),
    capital_pagado NUMBER(15,2),
    interes_pagado NUMBER(15,2),
    monto_total_pagado NUMBER(15,2),
    fecha_pago DATE,
    fecha_programada DATE,
    estado_pago VARCHAR2(20) DEFAULT 'PENDIENTE' CHECK (estado_pago IN ('PENDIENTE', 'PAGADO', 'CANCELADO')),
    fecha_creacion DATE DEFAULT SYSDATE,
    CONSTRAINT fk_pago_inv_inversion FOREIGN KEY (id_inversion) REFERENCES inversiones(id_inversion)
);

CREATE SEQUENCE seq_pagos_inversiones START WITH 1 INCREMENT BY 1;

COMMENT ON TABLE pagos_inversiones IS 'Tabla que registra los pagos programados y realizados de las inversiones';
COMMENT ON COLUMN pagos_inversiones.estado_pago IS 'PENDIENTE (no pagado), PAGADO (ya pagado), CANCELADO (cancelado)';

-- ============================================================================
-- 4.5 TABLA DE PRÉSTAMOS - Operaciones de salida de capital
-- ============================================================================

CREATE TABLE prestamos (
    id_prestamo NUMBER(15) PRIMARY KEY,
    id_usuario NUMBER(10) NOT NULL,
    id_moneda NUMBER(5) NOT NULL,
    entidad_financiera VARCHAR2(100) NOT NULL,
    capital_prestado NUMBER(15,2) NOT NULL,
    tasa_interes NUMBER(5,2) NOT NULL,
    plazo_dias NUMBER(5) NOT NULL,
    modalidad_pago VARCHAR2(20) NOT NULL CHECK (modalidad_pago IN ('MENSUAL', 'FINAL')),
    fecha_inicio DATE DEFAULT SYSDATE NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    interes_total_proyectado NUMBER(15,2),
    monto_total_a_recibir NUMBER(15,2),
    estado VARCHAR2(20) DEFAULT 'VIGENTE' CHECK (estado IN ('VIGENTE', 'VENCIDO', 'CANCELADO')),
    fecha_creacion DATE DEFAULT SYSDATE,
    observaciones VARCHAR2(500),
    CONSTRAINT fk_prest_usuario FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario),
    CONSTRAINT fk_prest_moneda FOREIGN KEY (id_moneda) REFERENCES monedas(id_moneda)
);

CREATE SEQUENCE seq_prestamos START WITH 2000 INCREMENT BY 1;

COMMENT ON TABLE prestamos IS 'Tabla que registra los préstamos colocados en entidades financieras';
COMMENT ON COLUMN prestamos.entidad_financiera IS 'Nombre de la institución financiera donde se coloca el préstamo';
COMMENT ON COLUMN prestamos.estado IS 'VIGENTE (activo), VENCIDO (plazo terminó), CANCELADO (cancelado manualmente)';

-- ============================================================================
-- 4.6 TABLA DE PAGOS DE PRÉSTAMOS - Detalles de pagos
-- ============================================================================

CREATE TABLE pagos_prestamos (
    id_pago_prestamo NUMBER(15) PRIMARY KEY,
    id_prestamo NUMBER(15) NOT NULL,
    numero_pago NUMBER(3),
    capital_pagado NUMBER(15,2),
    interes_pagado NUMBER(15,2),
    monto_total_pagado NUMBER(15,2),
    fecha_pago DATE,
    fecha_programada DATE,
    estado_pago VARCHAR2(20) DEFAULT 'PENDIENTE' CHECK (estado_pago IN ('PENDIENTE', 'RECIBIDO', 'CANCELADO')),
    fecha_creacion DATE DEFAULT SYSDATE,
    CONSTRAINT fk_pago_prest_prestamo FOREIGN KEY (id_prestamo) REFERENCES prestamos(id_prestamo)
);

CREATE SEQUENCE seq_pagos_prestamos START WITH 1 INCREMENT BY 1;

COMMENT ON TABLE pagos_prestamos IS 'Tabla que registra los pagos programados y recibidos de los préstamos';
COMMENT ON COLUMN pagos_prestamos.estado_pago IS 'PENDIENTE (no recibido), RECIBIDO (ya recibido), CANCELADO (cancelado)';

-- ============================================================================
-- 4.7 TABLA DE SALDO DIARIO DE FONDOS - Consolidado diario
-- ============================================================================

CREATE TABLE saldo_diario_fondos (
    id_saldo NUMBER(15) PRIMARY KEY,
    id_moneda NUMBER(5) NOT NULL,
    fecha DATE DEFAULT SYSDATE NOT NULL,
    capital_vigente_inversionistas NUMBER(15,2) DEFAULT 0,
    capital_colocado_sistema_financiero NUMBER(15,2) DEFAULT 0,
    capital_disponible NUMBER(15,2) DEFAULT 0,
    capital_total NUMBER(15,2) DEFAULT 0,
    fecha_creacion DATE DEFAULT SYSDATE,
    CONSTRAINT fk_saldo_moneda FOREIGN KEY (id_moneda) REFERENCES monedas(id_moneda),
    CONSTRAINT uk_saldo_fecha_moneda UNIQUE (fecha, id_moneda)
);

CREATE SEQUENCE seq_saldo_diario_fondos START WITH 1 INCREMENT BY 1;

COMMENT ON TABLE saldo_diario_fondos IS 'Tabla que mantiene el saldo consolidado diario de fondos por moneda';
COMMENT ON COLUMN saldo_diario_fondos.capital_vigente_inversionistas IS 'Total del capital de inversionistas actualmente en el fondo';
COMMENT ON COLUMN saldo_diario_fondos.capital_colocado_sistema_financiero IS 'Total del capital colocado en el sistema financiero';
COMMENT ON COLUMN saldo_diario_fondos.capital_disponible IS 'Capital disponible para nuevas inversiones (vigente - colocado)';

-- ============================================================================
-- 4.8 TABLA DE AUDITORÍA - Registro de cambios
-- ============================================================================

CREATE TABLE auditoria_operaciones (
    id_auditoria NUMBER(15) PRIMARY KEY,
    id_usuario NUMBER(10),
    tipo_operacion VARCHAR2(50),
    tabla_afectada VARCHAR2(50),
    registro_id NUMBER(15),
    descripcion VARCHAR2(500),
    fecha_operacion DATE DEFAULT SYSDATE,
    accion VARCHAR2(20) CHECK (accion IN ('INSERT', 'UPDATE', 'DELETE')),
    CONSTRAINT fk_audit_usuario FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
);

CREATE SEQUENCE seq_auditoria_operaciones START WITH 1 INCREMENT BY 1;

COMMENT ON TABLE auditoria_operaciones IS 'Tabla que registra todas las operaciones realizadas en la base de datos para auditoría';
COMMENT ON COLUMN auditoria_operaciones.accion IS 'Tipo de operación: INSERT (inserción), UPDATE (actualización), DELETE (eliminación)';

-- ============================================================================
-- PASO 5: CREAR ÍNDICES PARA OPTIMIZACIÓN
-- ============================================================================

CREATE INDEX idx_usuarios_estado ON usuarios(estado);
CREATE INDEX idx_usuarios_fecha_creacion ON usuarios(fecha_creacion);

CREATE INDEX idx_inversiones_usuario ON inversiones(id_usuario);
CREATE INDEX idx_inversiones_moneda ON inversiones(id_moneda);
CREATE INDEX idx_inversiones_estado ON inversiones(estado);
CREATE INDEX idx_inversiones_fecha_vencimiento ON inversiones(fecha_vencimiento);

CREATE INDEX idx_pagos_inv_inversion ON pagos_inversiones(id_inversion);
CREATE INDEX idx_pagos_inv_estado ON pagos_inversiones(estado_pago);
CREATE INDEX idx_pagos_inv_fecha ON pagos_inversiones(fecha_pago);

CREATE INDEX idx_prestamos_usuario ON prestamos(id_usuario);
CREATE INDEX idx_prestamos_moneda ON prestamos(id_moneda);
CREATE INDEX idx_prestamos_estado ON prestamos(estado);
CREATE INDEX idx_prestamos_fecha_vencimiento ON prestamos(fecha_vencimiento);

CREATE INDEX idx_pagos_prest_prestamo ON pagos_prestamos(id_prestamo);
CREATE INDEX idx_pagos_prest_estado ON pagos_prestamos(estado_pago);
CREATE INDEX idx_pagos_prest_fecha ON pagos_prestamos(fecha_pago);

CREATE INDEX idx_saldo_moneda ON saldo_diario_fondos(id_moneda);
CREATE INDEX idx_saldo_fecha ON saldo_diario_fondos(fecha);

CREATE INDEX idx_auditoria_usuario ON auditoria_operaciones(id_usuario);
CREATE INDEX idx_auditoria_fecha ON auditoria_operaciones(fecha_operacion);

-- ============================================================================
-- PASO 6: INSERTAR DATOS INICIALES
-- ============================================================================

-- Insertar usuario inicial de acceso
INSERT INTO usuarios (id_usuario, usuario, contrasena, nombre_completo, estado, fecha_creacion)
VALUES (seq_usuarios.NEXTVAL, 'USR_PRG2_A', 'umg123', 'Usuario Administrador', 'ACTIVO', SYSDATE);

-- Insertar monedas
INSERT INTO monedas VALUES (1, 'GTQ', 'Quetzal Guatemalteco', 'Q', 'ACTIVO');
INSERT INTO monedas VALUES (2, 'USD', 'Dólar Estadounidense', '$', 'ACTIVO');
INSERT INTO monedas VALUES (3, 'EUR', 'Euro', '€', 'ACTIVO');

COMMIT;

-- ============================================================================
-- PASO 7: CREAR VISTAS
-- ============================================================================

-- Vista de inversiones activas
CREATE OR REPLACE VIEW v_inversiones_activas AS
SELECT 
    i.id_inversion,
    u.usuario,
    u.nombre_completo,
    m.codigo_moneda,
    m.simbolo,
    i.capital_inicial,
    i.tasa_interes,
    i.plazo_dias,
    i.modalidad_pago,
    i.fecha_inicio,
    i.fecha_vencimiento,
    i.interes_total_proyectado,
    i.monto_total_a_recibir,
    i.estado,
    TRUNC(i.fecha_vencimiento - SYSDATE) AS dias_restantes
FROM inversiones i
JOIN usuarios u ON i.id_usuario = u.id_usuario
JOIN monedas m ON i.id_moneda = m.id_moneda
WHERE i.estado = 'VIGENTE'
ORDER BY i.fecha_vencimiento;

COMMENT ON VIEW v_inversiones_activas IS 'Vista que muestra todas las inversiones vigentes con información consolidada';

-- Vista de préstamos activos
CREATE OR REPLACE VIEW v_prestamos_activos AS
SELECT 
    p.id_prestamo,
    u.usuario,
    u.nombre_completo,
    m.codigo_moneda,
    m.simbolo,
    p.entidad_financiera,
    p.capital_prestado,
    p.tasa_interes,
    p.plazo_dias,
    p.modalidad_pago,
    p.fecha_inicio,
    p.fecha_vencimiento,
    p.interes_total_proyectado,
    p.monto_total_a_recibir,
    p.estado,
    TRUNC(p.fecha_vencimiento - SYSDATE) AS dias_restantes
FROM prestamos p
JOIN usuarios u ON p.id_usuario = u.id_usuario
JOIN monedas m ON p.id_moneda = m.id_moneda
WHERE p.estado = 'VIGENTE'
ORDER BY p.fecha_vencimiento;

COMMENT ON VIEW v_prestamos_activos IS 'Vista que muestra todos los préstamos vigentes con información consolidada';

-- Vista de saldo consolidado
CREATE OR REPLACE VIEW v_saldo_consolidado AS
SELECT 
    m.codigo_moneda,
    m.nombre_moneda,
    m.simbolo,
    sdf.fecha,
    sdf.capital_vigente_inversionistas,
    sdf.capital_colocado_sistema_financiero,
    sdf.capital_disponible,
    sdf.capital_total
FROM saldo_diario_fondos sdf
JOIN monedas m ON sdf.id_moneda = m.id_moneda
WHERE sdf.fecha = (SELECT MAX(fecha) FROM saldo_diario_fondos WHERE id_moneda = sdf.id_moneda)
ORDER BY m.codigo_moneda;

COMMENT ON VIEW v_saldo_consolidado IS 'Vista que muestra el saldo actual consolidado por moneda';

-- ============================================================================
-- PASO 8: CREAR PROCEDIMIENTOS ALMACENADOS
-- ============================================================================

-- Procedimiento para calcular intereses de inversión (MODALIDAD MENSUAL)
CREATE OR REPLACE PROCEDURE sp_calcular_pagos_inversion_mensual(
    p_id_inversion IN NUMBER
) AS
    v_capital NUMBER(15,2);
    v_tasa NUMBER(5,2);
    v_plazo NUMBER(5);
    v_interes_mensual NUMBER(15,2);
    v_num_pagos NUMBER(3) := 0;
    v_fecha_pago DATE;
    v_fecha_inicio DATE;
    v_interes_total NUMBER(15,2) := 0;
BEGIN
    -- Obtener datos de la inversión
    SELECT capital_inicial, tasa_interes, plazo_dias, fecha_inicio
    INTO v_capital, v_tasa, v_plazo, v_fecha_inicio
    FROM inversiones
    WHERE id_inversion = p_id_inversion;
    
    -- Calcular número de pagos mensuales (cada 30 días)
    v_num_pagos := TRUNC(v_plazo / 30);
    
    -- Calcular interés mensual
    v_interes_mensual := (v_capital * v_tasa / 100) / 12;
    
    -- Generar pagos mensuales
    FOR i IN 1..v_num_pagos LOOP
        v_fecha_pago := v_fecha_inicio + (i * 30);
        v_interes_total := v_interes_total + v_interes_mensual;
        
        INSERT INTO pagos_inversiones (
            id_pago_inversion, id_inversion, numero_pago, capital_pagado,
            interes_pagado, monto_total_pagado, fecha_programada, estado_pago
        ) VALUES (
            seq_pagos_inversiones.NEXTVAL, p_id_inversion, i, 0,
            v_interes_mensual, v_interes_mensual, v_fecha_pago, 'PENDIENTE'
        );
    END LOOP;
    
    -- Pago final de capital más interés restante
    v_fecha_pago := v_fecha_inicio + v_plazo;
    v_interes_mensual := (v_capital * v_tasa / 100) - v_interes_total;
    
    INSERT INTO pagos_inversiones (
        id_pago_inversion, id_inversion, numero_pago, capital_pagado,
        interes_pagado, monto_total_pagado, fecha_programada, estado_pago
    ) VALUES (
        seq_pagos_inversiones.NEXTVAL, p_id_inversion, v_num_pagos + 1, v_capital,
        v_interes_mensual, v_capital + v_interes_mensual, v_fecha_pago, 'PENDIENTE'
    );
    
    -- Actualizar inversión con totales
    UPDATE inversiones 
    SET interes_total_proyectado = v_interes_total + v_interes_mensual,
        monto_total_a_recibir = v_capital + v_interes_total + v_interes_mensual
    WHERE id_inversion = p_id_inversion;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Pagos mensuales calculados para inversión ' || p_id_inversion);
    
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        DBMS_OUTPUT.PUT_LINE('Error: Inversión no encontrada');
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        ROLLBACK;
END sp_calcular_pagos_inversion_mensual;
/

-- Procedimiento para calcular intereses de inversión (MODALIDAD FINAL)
CREATE OR REPLACE PROCEDURE sp_calcular_pagos_inversion_final(
    p_id_inversion IN NUMBER
) AS
    v_capital NUMBER(15,2);
    v_tasa NUMBER(5,2);
    v_plazo NUMBER(5);
    v_interes_total NUMBER(15,2);
    v_fecha_vencimiento DATE;
BEGIN
    -- Obtener datos de la inversión
    SELECT capital_inicial, tasa_interes, plazo_dias, fecha_vencimiento
    INTO v_capital, v_tasa, v_plazo, v_fecha_vencimiento
    FROM inversiones
    WHERE id_inversion = p_id_inversion;
    
    -- Calcular interés total (Interés = Capital * (Tasa/100) * (Plazo/365))
    v_interes_total := v_capital * (v_tasa / 100) * (v_plazo / 365);
    
    -- Registrar pago único al vencimiento
    INSERT INTO pagos_inversiones (
        id_pago_inversion, id_inversion, numero_pago, capital_pagado,
        interes_pagado, monto_total_pagado, fecha_programada, estado_pago
    ) VALUES (
        seq_pagos_inversiones.NEXTVAL, p_id_inversion, 1, v_capital,
        v_interes_total, v_capital + v_interes_total, v_fecha_vencimiento, 'PENDIENTE'
    );
    
    -- Actualizar inversión con totales
    UPDATE inversiones 
    SET interes_total_proyectado = v_interes_total,
        monto_total_a_recibir = v_capital + v_interes_total
    WHERE id_inversion = p_id_inversion;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Pago final calculado para inversión ' || p_id_inversion);
    
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        DBMS_OUTPUT.PUT_LINE('Error: Inversión no encontrada');
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        ROLLBACK;
END sp_calcular_pagos_inversion_final;
/

-- Procedimiento para calcular intereses de préstamo (MODALIDAD MENSUAL)
CREATE OR REPLACE PROCEDURE sp_calcular_pagos_prestamo_mensual(
    p_id_prestamo IN NUMBER
) AS
    v_capital NUMBER(15,2);
    v_tasa NUMBER(5,2);
    v_plazo NUMBER(5);
    v_interes_mensual NUMBER(15,2);
    v_num_pagos NUMBER(3) := 0;
    v_fecha_pago DATE;
    v_fecha_inicio DATE;
    v_interes_total NUMBER(15,2) := 0;
BEGIN
    -- Obtener datos del préstamo
    SELECT capital_prestado, tasa_interes, plazo_dias, fecha_inicio
    INTO v_capital, v_tasa, v_plazo, v_fecha_inicio
    FROM prestamos
    WHERE id_prestamo = p_id_prestamo;
    
    -- Calcular número de pagos mensuales
    v_num_pagos := TRUNC(v_plazo / 30);
    
    -- Calcular interés mensual
    v_interes_mensual := (v_capital * v_tasa / 100) / 12;
    
    -- Generar pagos mensuales
    FOR i IN 1..v_num_pagos LOOP
        v_fecha_pago := v_fecha_inicio + (i * 30);
        v_interes_total := v_interes_total + v_interes_mensual;
        
        INSERT INTO pagos_prestamos (
            id_pago_prestamo, id_prestamo, numero_pago, capital_pagado,
            interes_pagado, monto_total_pagado, fecha_programada, estado_pago
        ) VALUES (
            seq_pagos_prestamos.NEXTVAL, p_id_prestamo, i, 0,
            v_interes_mensual, v_interes_mensual, v_fecha_pago, 'PENDIENTE'
        );
    END LOOP;
    
    -- Pago final de capital más interés restante
    v_fecha_pago := v_fecha_inicio + v_plazo;
    v_interes_mensual := (v_capital * v_tasa / 100) - v_interes_total;
    
    INSERT INTO pagos_prestamos (
        id_pago_prestamo, id_prestamo, numero_pago, capital_pagado,
        interes_pagado, monto_total_pagado, fecha_programada, estado_pago
    ) VALUES (
        seq_pagos_prestamos.NEXTVAL, p_id_prestamo, v_num_pagos + 1, v_capital,
        v_interes_mensual, v_capital + v_interes_mensual, v_fecha_pago, 'PENDIENTE'
    );
    
    -- Actualizar préstamo con totales
    UPDATE prestamos 
    SET interes_total_proyectado = v_interes_total + v_interes_mensual,
        monto_total_a_recibir = v_capital + v_interes_total + v_interes_mensual
    WHERE id_prestamo = p_id_prestamo;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Pagos mensuales calculados para préstamo ' || p_id_prestamo);
    
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        DBMS_OUTPUT.PUT_LINE('Error: Préstamo no encontrado');
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        ROLLBACK;
END sp_calcular_pagos_prestamo_mensual;
/

-- Procedimiento para calcular intereses de préstamo (MODALIDAD FINAL)
CREATE OR REPLACE PROCEDURE sp_calcular_pagos_prestamo_final(
    p_id_prestamo IN NUMBER
) AS
    v_capital NUMBER(15,2);
    v_tasa NUMBER(5,2);
    v_plazo NUMBER(5);
    v_interes_total NUMBER(15,2);
    v_fecha_vencimiento DATE;
BEGIN
    -- Obtener datos del préstamo
    SELECT capital_prestado, tasa_interes, plazo_dias, fecha_vencimiento
    INTO v_capital, v_tasa, v_plazo, v_fecha_vencimiento
    FROM prestamos
    WHERE id_prestamo = p_id_prestamo;
    
    -- Calcular interés total
    v_interes_total := v_capital * (v_tasa / 100) * (v_plazo / 365);
    
    -- Registrar pago único al vencimiento
    INSERT INTO pagos_prestamos (
        id_pago_prestamo, id_prestamo, numero_pago, capital_pagado,
        interes_pagado, monto_total_pagado, fecha_programada, estado_pago
    ) VALUES (
        seq_pagos_prestamos.NEXTVAL, p_id_prestamo, 1, v_capital,
        v_interes_total, v_capital + v_interes_total, v_fecha_vencimiento, 'PENDIENTE'
    );
    
    -- Actualizar préstamo con totales
    UPDATE prestamos 
    SET interes_total_proyectado = v_interes_total,
        monto_total_a_recibir = v_capital + v_interes_total
    WHERE id_prestamo = p_id_prestamo;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Pago final calculado para préstamo ' || p_id_prestamo);
    
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        DBMS_OUTPUT.PUT_LINE('Error: Préstamo no encontrado');
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        ROLLBACK;
END sp_calcular_pagos_prestamo_final;
/

-- Procedimiento para actualizar saldo diario de fondos
CREATE OR REPLACE PROCEDURE sp_actualizar_saldo_diario(
    p_id_moneda IN NUMBER,
    p_fecha IN DATE DEFAULT SYSDATE
) AS
    v_capital_vigente NUMBER(15,2) := 0;
    v_capital_colocado NUMBER(15,2) := 0;
    v_capital_disponible NUMBER(15,2) := 0;
    v_id_saldo NUMBER(15);
    v_fecha_saldo DATE;
BEGIN
    v_fecha_saldo := TRUNC(p_fecha);
    
    -- Calcular capital vigente de inversionistas
    SELECT COALESCE(SUM(capital_inicial), 0)
    INTO v_capital_vigente
    FROM inversiones
    WHERE id_moneda = p_id_moneda
    AND estado = 'VIGENTE'
    AND TRUNC(fecha_inicio) <= v_fecha_saldo;
    
    -- Calcular capital colocado en sistema financiero
    SELECT COALESCE(SUM(capital_prestado), 0)
    INTO v_capital_colocado
    FROM prestamos
    WHERE id_moneda = p_id_moneda
    AND estado = 'VIGENTE'
    AND TRUNC(fecha_inicio) <= v_fecha_saldo;
    
    -- Capital disponible es la diferencia
    v_capital_disponible := v_capital_vigente - v_capital_colocado;
    
    -- Verificar si existe registro del día
    BEGIN
        SELECT id_saldo INTO v_id_saldo
        FROM saldo_diario_fondos
        WHERE id_moneda = p_id_moneda
        AND fecha = v_fecha_saldo;
        
        -- Si existe, actualizar
        UPDATE saldo_diario_fondos
        SET capital_vigente_inversionistas = v_capital_vigente,
            capital_colocado_sistema_financiero = v_capital_colocado,
            capital_disponible = v_capital_disponible,
            capital_total = v_capital_vigente
        WHERE id_saldo = v_id_saldo;
        
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            -- Si no existe, insertar
            INSERT INTO saldo_diario_fondos (
                id_saldo, id_moneda, fecha, capital_vigente_inversionistas,
                capital_colocado_sistema_financiero, capital_disponible, capital_total
            ) VALUES (
                seq_saldo_diario_fondos.NEXTVAL, p_id_moneda, v_fecha_saldo,
                v_capital_vigente, v_capital_colocado, v_capital_disponible, v_capital_vigente
            );
    END;
    
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Saldo diario actualizado para moneda ' || p_id_moneda);
    
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        ROLLBACK;
END sp_actualizar_saldo_diario;
/

-- ============================================================================
-- PASO 9: MENSAJE DE FINALIZACIÓN
-- ============================================================================

BEGIN
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('╔════════════════════════════════════════════════════════════════╗');
    DBMS_OUTPUT.PUT_LINE('║        ✓ BASE DE DATOS CREADA EXITOSAMENTE                    ║');
    DBMS_OUTPUT.PUT_LINE('║                                                                ║');
    DBMS_OUTPUT.PUT_LINE('║  Usuario de base de datos: banco_usr                           ║');
    DBMS_OUTPUT.PUT_LINE('║  Contraseña: BancoApp2025!                                     ║');
    DBMS_OUTPUT.PUT_LINE('║                                                                ║');
    DBMS_OUTPUT.PUT_LINE('║  8 Tablas creadas                                              ║');
    DBMS_OUTPUT.PUT_LINE('║  5 Procedimientos almacenados                                  ║');
    DBMS_OUTPUT.PUT_LINE('║  3 Vistas creadas                                              ║');
    DBMS_OUTPUT.PUT_LINE('║  14 Índices creados                                            ║');
    DBMS_OUTPUT.PUT_LINE('║                                                                ║');
    DBMS_OUTPUT.PUT_LINE('║  Usuario inicial: USR_PRG2_A / umg123                          ║');
    DBMS_OUTPUT.PUT_LINE('║  Monedas: GTQ, USD, EUR                                        ║');
    DBMS_OUTPUT.PUT_LINE('╚════════════════════════════════════════════════════════════════╝');
    DBMS_OUTPUT.PUT_LINE('');
END;
/

COMMIT;

-- ============================================================================
-- FIN DEL SCRIPT
-- ============================================================================