using BACKEND_CREDITOS.Models;
using BACKEND_CREDITOS.Data;
using Oracle.ManagedDataAccess.Client;
using System.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace BACKEND_CREDITOS.Services
{
    // ============================================================================
    // INTERFACES DE SERVICIOS
    // ============================================================================

    public interface IAuthService
    {
        Task<UsuarioLoginResponse?> Login(UsuarioLoginRequest request);
        Task<bool> Registrar(UsuarioRegistroRequest request);
        Task<bool> CambiarContrasena(int idUsuario, CambiarContrasenaRequest request);
        Task<bool> RecuperarContrasena(string usuario, string nuevaContrasena);
        string GenerarToken(Usuario usuario);
    }

    public interface IUsuarioService
    {
        Task<UsuarioDto?> ObtenerPorId(int id);
        Task<UsuarioDto?> ObtenerPorUsuario(string usuario);
        Task<List<UsuarioDto>> ObtenerTodos();
        Task<bool> Actualizar(int id, UsuarioDto usuario);
    }

    public interface IMonedaService
    {
        Task<List<MonedaDto>> ObtenerTodas();
        Task<MonedaDto?> ObtenerPorId(int id);
        Task<MonedaDto?> ObtenerPorCodigo(string codigo);
    }

    public interface IInversionService
    {
        Task<int> Crear(int idUsuario, InversionCreateRequest request);
        Task<InversionDto?> ObtenerPorId(int id);
        Task<List<InversionDto>> ObtenerTodas(int? idUsuario = null);
        Task<List<InversionDto>> ObtenerActivas(int? idUsuario = null);
        Task<List<PagoInversionDto>> ObtenerPagos(int idInversion);
        Task<bool> Cancelar(int id);
        Task<bool> ActualizarEstados();
    }

    public interface IPrestamoService
    {
        Task<int> Crear(int idUsuario, PrestamoCreateRequest request);
        Task<PrestamoDto?> ObtenerPorId(int id);
        Task<List<PrestamoDto>> ObtenerTodas(int? idUsuario = null);
        Task<List<PrestamoDto>> ObtenerActivos(int? idUsuario = null);
        Task<List<PagoPrestamoDto>> ObtenerPagos(int idPrestamo);
        Task<bool> Cancelar(int id);
        Task<bool> ActualizarEstados();
    }

    public interface ISaldoService
    {
        Task<SaldoDto?> ObtenerSaldoActual(int idMoneda);
        Task<List<SaldoDto>> ObtenerSaldoConsolidado();
        Task<List<SaldoDto>> ObtenerHistoricoMoneda(int idMoneda, int dias = 30);
        Task<bool> ActualizarSaldos();
    }

    public interface IRolService
    {
        Task<RolDto?> ObtenerPorId(int id);
        Task<List<RolDto>> ObtenerTodos();
        Task<int> Crear(RolCreateRequest request);
        Task<bool> Actualizar(int id, RolUpdateRequest request);
        Task<bool> Eliminar(int id);
        Task<bool> AsignarRolAUsuario(int idUsuario, int idRol, int asignadoPor);
        Task<bool> RemoverRolDeUsuario(int idUsuario, int idRol);
        Task<List<UsuarioRolDto>> ObtenerRolesDeUsuario(int idUsuario);
        Task<List<UsuarioRolDto>> ObtenerUsuariosConRol(int idRol);
    }

    // ============================================================================
    // IMPLEMENTACIÓN - SERVICIO DE AUTENTICACIÓN
    // ============================================================================

    public class AuthService : IAuthService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;

        public AuthService(IConnectionRepository connectionRepository, IConfiguration configuration, ILogger<AuthService> logger)
        {
            _connectionRepository = connectionRepository;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<UsuarioLoginResponse?> Login(UsuarioLoginRequest request)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id_usuario, usuario, nombre_completo, contrasena FROM usuarios WHERE usuario = :usuario AND estado = 'ACTIVO'";
                        command.Parameters.Add(new OracleParameter("usuario", OracleDbType.Varchar2) { Value = request.Usuario });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                var idUsuario = reader.GetInt32(0);
                                var usuario = reader.GetString(1);
                                var nombreCompleto = reader.GetString(2);
                                var contrasenaAlmacenada = reader.GetString(3);

                                if (VerificarContrasena(request.Contrasena, contrasenaAlmacenada))
                                {
                                    var usuarioEntity = new Usuario
                                    {
                                        IdUsuario = idUsuario,
                                        Nombre = usuario,
                                        NombreCompleto = nombreCompleto
                                    };

                                    var token = GenerarToken(usuarioEntity);
                                    var expirationMinutes = _configuration.GetValue<int>("Jwt:ExpirationMinutes", 60);

                                    _logger.LogInformation($"Login exitoso para usuario: {usuario}");

                                    return new UsuarioLoginResponse
                                    {
                                        IdUsuario = idUsuario,
                                        Usuario = usuario,
                                        NombreCompleto = nombreCompleto,
                                        Token = token,
                                        TokenExpiration = DateTime.UtcNow.AddMinutes(expirationMinutes)
                                    };
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error en login: {ex.Message}");
            }

            return null;
        }

        public async Task<bool> Registrar(UsuarioRegistroRequest request)
        {
            try
            {
                if (request.Contrasena != request.ConfirmarContrasena)
                    return false;

                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT COUNT(*) FROM usuarios WHERE usuario = :usuario";
                        command.Parameters.Add(new OracleParameter("usuario", OracleDbType.Varchar2) { Value = request.Usuario });
                        var count = (decimal)await command.ExecuteScalarAsync()!;
                        if (count > 0) return false;
                    }

                    var contrasenaEncriptada = EncriptarContrasena(request.Contrasena);

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            INSERT INTO usuarios (id_usuario, usuario, contrasena, nombre_completo, correo_electronico, estado, fecha_creacion, fecha_cambio_contrasena)
                            VALUES (seq_usuarios.NEXTVAL, :usuario, :contrasena, :nombreCompleto, :correo, 'ACTIVO', SYSDATE, SYSDATE)";

                        command.Parameters.Add(new OracleParameter("usuario", OracleDbType.Varchar2) { Value = request.Usuario });
                        command.Parameters.Add(new OracleParameter("contrasena", OracleDbType.Varchar2) { Value = contrasenaEncriptada });
                        command.Parameters.Add(new OracleParameter("nombreCompleto", OracleDbType.Varchar2) { Value = request.NombreCompleto });
                        command.Parameters.Add(new OracleParameter("correo", OracleDbType.Varchar2) { Value = request.CorreoElectronico ?? "" });

                        var result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error registrando usuario: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> CambiarContrasena(int idUsuario, CambiarContrasenaRequest request)
        {
            try
            {
                if (request.ContrasenaNueva != request.ConfirmarContrasenaNueva)
                    return false;

                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT contrasena FROM usuarios WHERE id_usuario = :idUsuario";
                        command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario });
                        var contrasenaActual = await command.ExecuteScalarAsync();
                        if (contrasenaActual == null || !VerificarContrasena(request.ContrasenaActual, contrasenaActual.ToString()!))
                            return false;
                    }

                    var nuevaContrasenaEncriptada = EncriptarContrasena(request.ContrasenaNueva);

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "UPDATE usuarios SET contrasena = :contrasena, fecha_cambio_contrasena = SYSDATE WHERE id_usuario = :idUsuario";
                        command.Parameters.Add(new OracleParameter("contrasena", OracleDbType.Varchar2) { Value = nuevaContrasenaEncriptada });
                        command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario });
                        var result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error cambiando contraseña: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> RecuperarContrasena(string usuario, string nuevaContrasena)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();
                    var contrasenaEncriptada = EncriptarContrasena(nuevaContrasena);

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "UPDATE usuarios SET contrasena = :contrasena, fecha_cambio_contrasena = SYSDATE WHERE usuario = :usuario";
                        command.Parameters.Add(new OracleParameter("contrasena", OracleDbType.Varchar2) { Value = contrasenaEncriptada });
                        command.Parameters.Add(new OracleParameter("usuario", OracleDbType.Varchar2) { Value = usuario });
                        var result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error recuperando contraseña: {ex.Message}");
                return false;
            }
        }

        public string GenerarToken(Usuario usuario)
        {
            var secretKey = _configuration.GetValue<string>("Jwt:SecretKey");
            var issuer = _configuration.GetValue<string>("Jwt:Issuer");
            var audience = _configuration.GetValue<string>("Jwt:Audience");
            var expirationMinutes = _configuration.GetValue<int>("Jwt:ExpirationMinutes", 60);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, usuario.IdUsuario.ToString()),
                new Claim(ClaimTypes.Name, usuario.Nombre),
                new Claim(ClaimTypes.GivenName, usuario.NombreCompleto),
                new Claim("email", usuario.CorreoElectronico ?? "")
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string EncriptarContrasena(string contrasena)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(contrasena));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        private bool VerificarContrasena(string contrasena, string hash)
        {
            var hashDeContrasena = EncriptarContrasena(contrasena);
            return hashDeContrasena == hash;
        }
    }

    // ============================================================================
    // IMPLEMENTACIÓN - SERVICIO DE USUARIOS
    // ============================================================================

    public class UsuarioService : IUsuarioService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<UsuarioService> _logger;

        public UsuarioService(IConnectionRepository connectionRepository, ILogger<UsuarioService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<UsuarioDto?> ObtenerPorId(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT id_usuario, usuario, nombre_completo, correo_electronico, estado, fecha_creacion, fecha_ultimo_acceso
                            FROM usuarios WHERE id_usuario = :idUsuario";
                        command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = id });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new UsuarioDto
                                {
                                    IdUsuario = reader.GetInt32(0),
                                    Usuario = reader.GetString(1),
                                    NombreCompleto = reader.GetString(2),
                                    CorreoElectronico = reader.IsDBNull(3) ? "" : reader.GetString(3),
                                    Estado = reader.GetString(4),
                                    FechaCreacion = reader.GetDateTime(5),
                                    FechaUltimoAcceso = reader.IsDBNull(6) ? null : reader.GetDateTime(6)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo usuario: {ex.Message}");
            }

            return null;
        }

        public async Task<UsuarioDto?> ObtenerPorUsuario(string usuario)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT id_usuario, usuario, nombre_completo, correo_electronico, estado, fecha_creacion, fecha_ultimo_acceso
                            FROM usuarios WHERE usuario = :usuario";
                        command.Parameters.Add(new OracleParameter("usuario", OracleDbType.Varchar2) { Value = usuario });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new UsuarioDto
                                {
                                    IdUsuario = reader.GetInt32(0),
                                    Usuario = reader.GetString(1),
                                    NombreCompleto = reader.GetString(2),
                                    CorreoElectronico = reader.IsDBNull(3) ? "" : reader.GetString(3),
                                    Estado = reader.GetString(4),
                                    FechaCreacion = reader.GetDateTime(5),
                                    FechaUltimoAcceso = reader.IsDBNull(6) ? null : reader.GetDateTime(6)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo usuario: {ex.Message}");
            }

            return null;
        }

        public async Task<List<UsuarioDto>> ObtenerTodos()
        {
            var usuarios = new List<UsuarioDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT id_usuario, usuario, nombre_completo, correo_electronico, estado, fecha_creacion, fecha_ultimo_acceso
                            FROM usuarios WHERE estado = 'ACTIVO' ORDER BY fecha_creacion DESC";

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                usuarios.Add(new UsuarioDto
                                {
                                    IdUsuario = reader.GetInt32(0),
                                    Usuario = reader.GetString(1),
                                    NombreCompleto = reader.GetString(2),
                                    CorreoElectronico = reader.IsDBNull(3) ? "" : reader.GetString(3),
                                    Estado = reader.GetString(4),
                                    FechaCreacion = reader.GetDateTime(5),
                                    FechaUltimoAcceso = reader.IsDBNull(6) ? null : reader.GetDateTime(6)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo usuarios: {ex.Message}");
            }

            return usuarios;
        }

        public async Task<bool> Actualizar(int id, UsuarioDto usuario)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE usuarios 
                            SET nombre_completo = :nombreCompleto, correo_electronico = :correo
                            WHERE id_usuario = :idUsuario";
                        command.Parameters.Add(new OracleParameter("nombreCompleto", OracleDbType.Varchar2) { Value = usuario.NombreCompleto });
                        command.Parameters.Add(new OracleParameter("correo", OracleDbType.Varchar2) { Value = usuario.CorreoElectronico ?? "" });
                        command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = id });

                        var result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando usuario: {ex.Message}");
                return false;
            }
        }
    }

    // ============================================================================
    // IMPLEMENTACIÓN - SERVICIO DE MONEDAS
    // ============================================================================

    public class MonedaService : IMonedaService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<MonedaService> _logger;

        public MonedaService(IConnectionRepository connectionRepository, ILogger<MonedaService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<List<MonedaDto>> ObtenerTodas()
        {
            var monedas = new List<MonedaDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id_moneda, codigo_moneda, nombre_moneda, simbolo, estado FROM monedas WHERE estado = 'ACTIVO' ORDER BY codigo_moneda";

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                monedas.Add(new MonedaDto
                                {
                                    IdMoneda = reader.GetInt32(0),
                                    CodigoMoneda = reader.GetString(1),
                                    NombreMoneda = reader.GetString(2),
                                    Simbolo = reader.GetString(3),
                                    Estado = reader.GetString(4)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo monedas: {ex.Message}");
            }

            return monedas;
        }

        public async Task<MonedaDto?> ObtenerPorId(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id_moneda, codigo_moneda, nombre_moneda, simbolo, estado FROM monedas WHERE id_moneda = :idMoneda";
                        command.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = id });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new MonedaDto
                                {
                                    IdMoneda = reader.GetInt32(0),
                                    CodigoMoneda = reader.GetString(1),
                                    NombreMoneda = reader.GetString(2),
                                    Simbolo = reader.GetString(3),
                                    Estado = reader.GetString(4)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo moneda: {ex.Message}");
            }

            return null;
        }

        public async Task<MonedaDto?> ObtenerPorCodigo(string codigo)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id_moneda, codigo_moneda, nombre_moneda, simbolo, estado FROM monedas WHERE codigo_moneda = :codigo";
                        command.Parameters.Add(new OracleParameter("codigo", OracleDbType.Varchar2) { Value = codigo });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new MonedaDto
                                {
                                    IdMoneda = reader.GetInt32(0),
                                    CodigoMoneda = reader.GetString(1),
                                    NombreMoneda = reader.GetString(2),
                                    Simbolo = reader.GetString(3),
                                    Estado = reader.GetString(4)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo moneda: {ex.Message}");
            }

            return null;
        }
    }

    // ============================================================================
    // SERVICIOS STUB - Para implementar completamente después
    // ============================================================================

    public class InversionService : IInversionService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<InversionService> _logger;

        public InversionService(IConnectionRepository connectionRepository, ILogger<InversionService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<int> Crear(int idUsuario, InversionCreateRequest request)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    // Validar moneda
                    using (var cmdValidar = (OracleCommand)connection.CreateCommand())
                    {
                        cmdValidar.CommandText = "SELECT COUNT(*) FROM monedas WHERE id_moneda = :idMoneda AND estado = 'ACTIVO'";
                        cmdValidar.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = request.IdMoneda });
                        var count = (decimal)await cmdValidar.ExecuteScalarAsync()!;
                        if (count == 0)
                        {
                            _logger.LogWarning($"Moneda {request.IdMoneda} no encontrada o inactiva");
                            return 0;
                        }
                    }

                    // Calcular fechas
                    var fechaInicio = DateTime.Now;
                    var fechaVencimiento = fechaInicio.AddDays(request.PlazoDias);

                    // Insertar inversión (sin calcular intereses, el SP lo hará)
                    int idInversion = 0;
                    using (var cmdInversion = (OracleCommand)connection.CreateCommand())
                    {
                        cmdInversion.CommandText = @"
                            INSERT INTO inversiones (
                                id_inversion, id_usuario, id_moneda, capital_inicial, tasa_interes,
                                plazo_dias, modalidad_pago, fecha_inicio, fecha_vencimiento,
                                estado, fecha_creacion, observaciones
                            ) VALUES (
                                seq_inversiones.NEXTVAL, :idUsuario, :idMoneda, :capitalInicial, :tasaInteres,
                                :plazoDias, :modalidadPago, :fechaInicio, :fechaVencimiento,
                                'VIGENTE', SYSDATE, :observaciones
                            ) RETURNING id_inversion INTO :idInversion";

                        cmdInversion.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario });
                        cmdInversion.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = request.IdMoneda });
                        cmdInversion.Parameters.Add(new OracleParameter("capitalInicial", OracleDbType.Decimal) { Value = request.CapitalInicial });
                        cmdInversion.Parameters.Add(new OracleParameter("tasaInteres", OracleDbType.Decimal) { Value = request.TasaInteres });
                        cmdInversion.Parameters.Add(new OracleParameter("plazoDias", OracleDbType.Int32) { Value = request.PlazoDias });
                        cmdInversion.Parameters.Add(new OracleParameter("modalidadPago", OracleDbType.Varchar2) { Value = request.ModalidadPago });
                        cmdInversion.Parameters.Add(new OracleParameter("fechaInicio", OracleDbType.Date) { Value = fechaInicio });
                        cmdInversion.Parameters.Add(new OracleParameter("fechaVencimiento", OracleDbType.Date) { Value = fechaVencimiento });
                        cmdInversion.Parameters.Add(new OracleParameter("observaciones", OracleDbType.Varchar2) { Value = request.Observaciones ?? "" });

                        var outParam = new OracleParameter("idInversion", OracleDbType.Int32) { Direction = ParameterDirection.Output };
                        cmdInversion.Parameters.Add(outParam);

                        await cmdInversion.ExecuteNonQueryAsync();
                        idInversion = ((OracleDecimal)outParam.Value).ToInt32();
                    }

                    // Llamar al stored procedure correspondiente según modalidad de pago
                    if (idInversion > 0)
                    {
                        using (var cmdSP = (OracleCommand)connection.CreateCommand())
                        {
                            if (request.ModalidadPago == "MENSUAL")
                            {
                                cmdSP.CommandText = "sp_calcular_pagos_inversion_mensual";
                            }
                            else // FINAL
                            {
                                cmdSP.CommandText = "sp_calcular_pagos_inversion_final";
                            }

                            cmdSP.CommandType = CommandType.StoredProcedure;
                            cmdSP.Parameters.Add(new OracleParameter("p_id_inversion", OracleDbType.Int32) { Value = idInversion });

                            await cmdSP.ExecuteNonQueryAsync();
                        }
                    }

                    _logger.LogInformation($"Inversión {idInversion} creada exitosamente usando stored procedure");
                    return idInversion;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creando inversión: {ex.Message}");
                return 0;
            }
        }

        public async Task<InversionDto?> ObtenerPorId(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT i.id_inversion, i.id_usuario, i.id_moneda, m.codigo_moneda, m.simbolo,
                                   i.capital_inicial, i.tasa_interes, i.plazo_dias, i.modalidad_pago,
                                   i.fecha_inicio, i.fecha_vencimiento, i.interes_total_proyectado,
                                   i.monto_total_a_recibir, i.estado
                            FROM inversiones i
                            JOIN monedas m ON i.id_moneda = m.id_moneda
                            WHERE i.id_inversion = :idInversion";

                        command.Parameters.Add(new OracleParameter("idInversion", OracleDbType.Int32) { Value = id });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(10);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                return new InversionDto
                                {
                                    IdInversion = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    CapitalInicial = reader.GetDecimal(5),
                                    TasaInteres = reader.GetDecimal(6),
                                    PlazoDias = reader.GetInt32(7),
                                    ModalidadPago = reader.GetString(8),
                                    FechaInicio = reader.GetDateTime(9),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(11),
                                    MontoTotalARecibir = reader.GetDecimal(12),
                                    Estado = reader.GetString(13),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo inversión {id}: {ex.Message}");
            }

            return null;
        }

        public async Task<List<InversionDto>> ObtenerTodas(int? idUsuario = null)
        {
            var inversiones = new List<InversionDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        var sql = @"
                            SELECT i.id_inversion, i.id_usuario, i.id_moneda, m.codigo_moneda, m.simbolo,
                                   i.capital_inicial, i.tasa_interes, i.plazo_dias, i.modalidad_pago,
                                   i.fecha_inicio, i.fecha_vencimiento, i.interes_total_proyectado,
                                   i.monto_total_a_recibir, i.estado
                            FROM inversiones i
                            JOIN monedas m ON i.id_moneda = m.id_moneda";

                        if (idUsuario.HasValue)
                        {
                            sql += " WHERE i.id_usuario = :idUsuario";
                            command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario.Value });
                        }

                        sql += " ORDER BY i.fecha_creacion DESC";
                        command.CommandText = sql;

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(10);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                inversiones.Add(new InversionDto
                                {
                                    IdInversion = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    CapitalInicial = reader.GetDecimal(5),
                                    TasaInteres = reader.GetDecimal(6),
                                    PlazoDias = reader.GetInt32(7),
                                    ModalidadPago = reader.GetString(8),
                                    FechaInicio = reader.GetDateTime(9),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(11),
                                    MontoTotalARecibir = reader.GetDecimal(12),
                                    Estado = reader.GetString(13),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo inversiones: {ex.Message}");
            }

            return inversiones;
        }

        public async Task<List<InversionDto>> ObtenerActivas(int? idUsuario = null)
        {
            var inversiones = new List<InversionDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        var sql = @"
                            SELECT i.id_inversion, i.id_usuario, i.id_moneda, m.codigo_moneda, m.simbolo,
                                   i.capital_inicial, i.tasa_interes, i.plazo_dias, i.modalidad_pago,
                                   i.fecha_inicio, i.fecha_vencimiento, i.interes_total_proyectado,
                                   i.monto_total_a_recibir, i.estado
                            FROM inversiones i
                            JOIN monedas m ON i.id_moneda = m.id_moneda
                            WHERE i.estado = 'VIGENTE'";

                        if (idUsuario.HasValue)
                        {
                            sql += " AND i.id_usuario = :idUsuario";
                            command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario.Value });
                        }

                        sql += " ORDER BY i.fecha_vencimiento ASC";
                        command.CommandText = sql;

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(10);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                inversiones.Add(new InversionDto
                                {
                                    IdInversion = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    CapitalInicial = reader.GetDecimal(5),
                                    TasaInteres = reader.GetDecimal(6),
                                    PlazoDias = reader.GetInt32(7),
                                    ModalidadPago = reader.GetString(8),
                                    FechaInicio = reader.GetDateTime(9),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(11),
                                    MontoTotalARecibir = reader.GetDecimal(12),
                                    Estado = reader.GetString(13),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo inversiones activas: {ex.Message}");
            }

            return inversiones;
        }

        public async Task<List<PagoInversionDto>> ObtenerPagos(int idInversion)
        {
            var pagos = new List<PagoInversionDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT id_pago_inversion, numero_pago, capital_pagado, interes_pagado,
                                   monto_total_pagado, fecha_programada, fecha_pago, estado_pago
                            FROM pagos_inversiones
                            WHERE id_inversion = :idInversion
                            ORDER BY numero_pago";

                        command.Parameters.Add(new OracleParameter("idInversion", OracleDbType.Int32) { Value = idInversion });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                pagos.Add(new PagoInversionDto
                                {
                                    IdPagoInversion = reader.GetInt32(0),
                                    NumeroPago = reader.GetInt32(1),
                                    CapitalPagado = reader.GetDecimal(2),
                                    InteresPagado = reader.GetDecimal(3),
                                    MontoTotalPagado = reader.GetDecimal(4),
                                    FechaProgramada = reader.GetDateTime(5),
                                    FechaPago = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                                    EstadoPago = reader.GetString(7)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo pagos de inversión {idInversion}: {ex.Message}");
            }

            return pagos;
        }

        public async Task<bool> Cancelar(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE inversiones
                            SET estado = 'CANCELADA'
                            WHERE id_inversion = :idInversion AND estado = 'VIGENTE'";

                        command.Parameters.Add(new OracleParameter("idInversion", OracleDbType.Int32) { Value = id });

                        var result = await command.ExecuteNonQueryAsync();

                        if (result > 0)
                        {
                            // Cancelar pagos pendientes
                            using (var cmdPagos = (OracleCommand)connection.CreateCommand())
                            {
                                cmdPagos.CommandText = @"
                                    UPDATE pagos_inversiones
                                    SET estado_pago = 'CANCELADO'
                                    WHERE id_inversion = :idInversion AND estado_pago = 'PENDIENTE'";

                                cmdPagos.Parameters.Add(new OracleParameter("idInversion", OracleDbType.Int32) { Value = id });
                                await cmdPagos.ExecuteNonQueryAsync();
                            }

                            _logger.LogInformation($"Inversión {id} cancelada");
                            return true;
                        }

                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error cancelando inversión {id}: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ActualizarEstados()
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    // Actualizar inversiones vencidas
                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE inversiones
                            SET estado = 'VENCIDA'
                            WHERE estado = 'VIGENTE'
                            AND fecha_vencimiento < SYSDATE";

                        var result = await command.ExecuteNonQueryAsync();
                        _logger.LogInformation($"{result} inversiones actualizadas a VENCIDA");
                    }

                    // Actualizar pagos vencidos
                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE pagos_inversiones
                            SET estado_pago = 'VENCIDO'
                            WHERE estado_pago = 'PENDIENTE'
                            AND fecha_programada < SYSDATE";

                        var result = await command.ExecuteNonQueryAsync();
                        _logger.LogInformation($"{result} pagos de inversión actualizados a VENCIDO");
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando estados de inversiones: {ex.Message}");
                return false;
            }
        }
    }

    public class PrestamoService : IPrestamoService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<PrestamoService> _logger;

        public PrestamoService(IConnectionRepository connectionRepository, ILogger<PrestamoService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<int> Crear(int idUsuario, PrestamoCreateRequest request)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    // Validar moneda
                    using (var cmdValidar = (OracleCommand)connection.CreateCommand())
                    {
                        cmdValidar.CommandText = "SELECT COUNT(*) FROM monedas WHERE id_moneda = :idMoneda AND estado = 'ACTIVO'";
                        cmdValidar.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = request.IdMoneda });
                        var count = (decimal)await cmdValidar.ExecuteScalarAsync()!;
                        if (count == 0)
                        {
                            _logger.LogWarning($"Moneda {request.IdMoneda} no encontrada o inactiva");
                            return 0;
                        }
                    }

                    // Calcular fechas
                    var fechaInicio = DateTime.Now;
                    var fechaVencimiento = fechaInicio.AddDays(request.PlazoDias);

                    // Insertar préstamo (sin calcular intereses, el SP lo hará)
                    int idPrestamo = 0;
                    using (var cmdPrestamo = (OracleCommand)connection.CreateCommand())
                    {
                        cmdPrestamo.CommandText = @"
                            INSERT INTO prestamos (
                                id_prestamo, id_usuario, id_moneda, entidad_financiera, capital_prestado,
                                tasa_interes, plazo_dias, modalidad_pago, fecha_inicio, fecha_vencimiento,
                                estado, fecha_creacion, observaciones
                            ) VALUES (
                                seq_prestamos.NEXTVAL, :idUsuario, :idMoneda, :entidadFinanciera, :capitalPrestado,
                                :tasaInteres, :plazoDias, :modalidadPago, :fechaInicio, :fechaVencimiento,
                                'VIGENTE', SYSDATE, :observaciones
                            ) RETURNING id_prestamo INTO :idPrestamo";

                        cmdPrestamo.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario });
                        cmdPrestamo.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = request.IdMoneda });
                        cmdPrestamo.Parameters.Add(new OracleParameter("entidadFinanciera", OracleDbType.Varchar2) { Value = request.EntidadFinanciera ?? "" });
                        cmdPrestamo.Parameters.Add(new OracleParameter("capitalPrestado", OracleDbType.Decimal) { Value = request.CapitalPrestado });
                        cmdPrestamo.Parameters.Add(new OracleParameter("tasaInteres", OracleDbType.Decimal) { Value = request.TasaInteres });
                        cmdPrestamo.Parameters.Add(new OracleParameter("plazoDias", OracleDbType.Int32) { Value = request.PlazoDias });
                        cmdPrestamo.Parameters.Add(new OracleParameter("modalidadPago", OracleDbType.Varchar2) { Value = request.ModalidadPago });
                        cmdPrestamo.Parameters.Add(new OracleParameter("fechaInicio", OracleDbType.Date) { Value = fechaInicio });
                        cmdPrestamo.Parameters.Add(new OracleParameter("fechaVencimiento", OracleDbType.Date) { Value = fechaVencimiento });
                        cmdPrestamo.Parameters.Add(new OracleParameter("observaciones", OracleDbType.Varchar2) { Value = request.Observaciones ?? "" });

                        var outParam = new OracleParameter("idPrestamo", OracleDbType.Int32) { Direction = ParameterDirection.Output };
                        cmdPrestamo.Parameters.Add(outParam);

                        await cmdPrestamo.ExecuteNonQueryAsync();
                        idPrestamo = ((OracleDecimal)outParam.Value).ToInt32();
                    }

                    // Llamar al stored procedure correspondiente según modalidad de pago
                    if (idPrestamo > 0)
                    {
                        using (var cmdSP = (OracleCommand)connection.CreateCommand())
                        {
                            if (request.ModalidadPago == "MENSUAL")
                            {
                                cmdSP.CommandText = "sp_calcular_pagos_prestamo_mensual";
                            }
                            else // FINAL
                            {
                                cmdSP.CommandText = "sp_calcular_pagos_prestamo_final";
                            }

                            cmdSP.CommandType = CommandType.StoredProcedure;
                            cmdSP.Parameters.Add(new OracleParameter("p_id_prestamo", OracleDbType.Int32) { Value = idPrestamo });

                            await cmdSP.ExecuteNonQueryAsync();
                        }
                    }

                    _logger.LogInformation($"Préstamo {idPrestamo} creado exitosamente usando stored procedure");
                    return idPrestamo;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creando préstamo: {ex.Message}");
                return 0;
            }
        }

        public async Task<PrestamoDto?> ObtenerPorId(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT p.id_prestamo, p.id_usuario, p.id_moneda, m.codigo_moneda, m.simbolo,
                                   p.entidad_financiera, p.capital_prestado, p.tasa_interes, p.plazo_dias,
                                   p.modalidad_pago, p.fecha_inicio, p.fecha_vencimiento,
                                   p.interes_total_proyectado, p.monto_total_a_recibir, p.estado
                            FROM prestamos p
                            JOIN monedas m ON p.id_moneda = m.id_moneda
                            WHERE p.id_prestamo = :idPrestamo";

                        command.Parameters.Add(new OracleParameter("idPrestamo", OracleDbType.Int32) { Value = id });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(11);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                return new PrestamoDto
                                {
                                    IdPrestamo = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    EntidadFinanciera = reader.GetString(5),
                                    CapitalPrestado = reader.GetDecimal(6),
                                    TasaInteres = reader.GetDecimal(7),
                                    PlazoDias = reader.GetInt32(8),
                                    ModalidadPago = reader.GetString(9),
                                    FechaInicio = reader.GetDateTime(10),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(12),
                                    MontoTotalARecibir = reader.GetDecimal(13),
                                    Estado = reader.GetString(14),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo préstamo {id}: {ex.Message}");
            }

            return null;
        }

        public async Task<List<PrestamoDto>> ObtenerTodas(int? idUsuario = null)
        {
            var prestamos = new List<PrestamoDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        var sql = @"
                            SELECT p.id_prestamo, p.id_usuario, p.id_moneda, m.codigo_moneda, m.simbolo,
                                   p.entidad_financiera, p.capital_prestado, p.tasa_interes, p.plazo_dias,
                                   p.modalidad_pago, p.fecha_inicio, p.fecha_vencimiento,
                                   p.interes_total_proyectado, p.monto_total_a_recibir, p.estado
                            FROM prestamos p
                            JOIN monedas m ON p.id_moneda = m.id_moneda";

                        if (idUsuario.HasValue)
                        {
                            sql += " WHERE p.id_usuario = :idUsuario";
                            command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario.Value });
                        }

                        sql += " ORDER BY p.fecha_creacion DESC";
                        command.CommandText = sql;

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(11);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                prestamos.Add(new PrestamoDto
                                {
                                    IdPrestamo = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    EntidadFinanciera = reader.GetString(5),
                                    CapitalPrestado = reader.GetDecimal(6),
                                    TasaInteres = reader.GetDecimal(7),
                                    PlazoDias = reader.GetInt32(8),
                                    ModalidadPago = reader.GetString(9),
                                    FechaInicio = reader.GetDateTime(10),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(12),
                                    MontoTotalARecibir = reader.GetDecimal(13),
                                    Estado = reader.GetString(14),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo préstamos: {ex.Message}");
            }

            return prestamos;
        }

        public async Task<List<PrestamoDto>> ObtenerActivos(int? idUsuario = null)
        {
            var prestamos = new List<PrestamoDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        var sql = @"
                            SELECT p.id_prestamo, p.id_usuario, p.id_moneda, m.codigo_moneda, m.simbolo,
                                   p.entidad_financiera, p.capital_prestado, p.tasa_interes, p.plazo_dias,
                                   p.modalidad_pago, p.fecha_inicio, p.fecha_vencimiento,
                                   p.interes_total_proyectado, p.monto_total_a_recibir, p.estado
                            FROM prestamos p
                            JOIN monedas m ON p.id_moneda = m.id_moneda
                            WHERE p.estado = 'VIGENTE'";

                        if (idUsuario.HasValue)
                        {
                            sql += " AND p.id_usuario = :idUsuario";
                            command.Parameters.Add(new OracleParameter("idUsuario", OracleDbType.Int32) { Value = idUsuario.Value });
                        }

                        sql += " ORDER BY p.fecha_vencimiento ASC";
                        command.CommandText = sql;

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var fechaVencimiento = reader.GetDateTime(11);
                                var diasRestantes = (fechaVencimiento - DateTime.Now).Days;

                                prestamos.Add(new PrestamoDto
                                {
                                    IdPrestamo = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdMoneda = reader.GetInt32(2),
                                    CodigoMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    EntidadFinanciera = reader.GetString(5),
                                    CapitalPrestado = reader.GetDecimal(6),
                                    TasaInteres = reader.GetDecimal(7),
                                    PlazoDias = reader.GetInt32(8),
                                    ModalidadPago = reader.GetString(9),
                                    FechaInicio = reader.GetDateTime(10),
                                    FechaVencimiento = fechaVencimiento,
                                    InteresTotalProyectado = reader.GetDecimal(12),
                                    MontoTotalARecibir = reader.GetDecimal(13),
                                    Estado = reader.GetString(14),
                                    DiasRestantes = diasRestantes < 0 ? 0 : diasRestantes
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo préstamos activos: {ex.Message}");
            }

            return prestamos;
        }

        public async Task<List<PagoPrestamoDto>> ObtenerPagos(int idPrestamo)
        {
            var pagos = new List<PagoPrestamoDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT id_pago_prestamo, numero_pago, capital_pagado, interes_pagado,
                                   monto_total_pagado, fecha_programada, fecha_pago, estado_pago
                            FROM pagos_prestamos
                            WHERE id_prestamo = :idPrestamo
                            ORDER BY numero_pago";

                        command.Parameters.Add(new OracleParameter("idPrestamo", OracleDbType.Int32) { Value = idPrestamo });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                pagos.Add(new PagoPrestamoDto
                                {
                                    IdPagoPrestamo = reader.GetInt32(0),
                                    NumeroPago = reader.GetInt32(1),
                                    CapitalPagado = reader.GetDecimal(2),
                                    InteresPagado = reader.GetDecimal(3),
                                    MontoTotalPagado = reader.GetDecimal(4),
                                    FechaProgramada = reader.GetDateTime(5),
                                    FechaPago = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                                    EstadoPago = reader.GetString(7)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo pagos de préstamo {idPrestamo}: {ex.Message}");
            }

            return pagos;
        }

        public async Task<bool> Cancelar(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE prestamos
                            SET estado = 'CANCELADO'
                            WHERE id_prestamo = :idPrestamo AND estado = 'VIGENTE'";

                        command.Parameters.Add(new OracleParameter("idPrestamo", OracleDbType.Int32) { Value = id });

                        var result = await command.ExecuteNonQueryAsync();

                        if (result > 0)
                        {
                            // Cancelar pagos pendientes
                            using (var cmdPagos = (OracleCommand)connection.CreateCommand())
                            {
                                cmdPagos.CommandText = @"
                                    UPDATE pagos_prestamos
                                    SET estado_pago = 'CANCELADO'
                                    WHERE id_prestamo = :idPrestamo AND estado_pago = 'PENDIENTE'";

                                cmdPagos.Parameters.Add(new OracleParameter("idPrestamo", OracleDbType.Int32) { Value = id });
                                await cmdPagos.ExecuteNonQueryAsync();
                            }

                            _logger.LogInformation($"Préstamo {id} cancelado");
                            return true;
                        }

                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error cancelando préstamo {id}: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ActualizarEstados()
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    // Actualizar préstamos vencidos
                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE prestamos
                            SET estado = 'VENCIDO'
                            WHERE estado = 'VIGENTE'
                            AND fecha_vencimiento < SYSDATE";

                        var result = await command.ExecuteNonQueryAsync();
                        _logger.LogInformation($"{result} préstamos actualizados a VENCIDO");
                    }

                    // Actualizar pagos vencidos
                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            UPDATE pagos_prestamos
                            SET estado_pago = 'VENCIDO'
                            WHERE estado_pago = 'PENDIENTE'
                            AND fecha_programada < SYSDATE";

                        var result = await command.ExecuteNonQueryAsync();
                        _logger.LogInformation($"{result} pagos de préstamo actualizados a VENCIDO");
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando estados de préstamos: {ex.Message}");
                return false;
            }
        }
    }

    public class SaldoService : ISaldoService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<SaldoService> _logger;

        public SaldoService(IConnectionRepository connectionRepository, ILogger<SaldoService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<SaldoDto?> ObtenerSaldoActual(int idMoneda)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT s.id_saldo, s.id_moneda, m.codigo_moneda, m.nombre_moneda, m.simbolo,
                                   s.fecha, s.capital_vigente_inversionistas, s.capital_colocado_sistema_financiero,
                                   s.capital_disponible, s.capital_total
                            FROM saldo_diario_fondos s
                            JOIN monedas m ON s.id_moneda = m.id_moneda
                            WHERE s.id_moneda = :idMoneda
                            AND s.fecha = (SELECT MAX(fecha) FROM saldo_diario_fondos WHERE id_moneda = :idMoneda)";

                        command.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = idMoneda });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new SaldoDto
                                {
                                    IdSaldo = reader.GetInt32(0),
                                    IdMoneda = reader.GetInt32(1),
                                    CodigoMoneda = reader.GetString(2),
                                    NombreMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    Fecha = reader.GetDateTime(5),
                                    CapitalVigenteInversionistas = reader.GetDecimal(6),
                                    CapitalColocadoSistemaFinanciero = reader.GetDecimal(7),
                                    CapitalDisponible = reader.GetDecimal(8),
                                    CapitalTotal = reader.GetDecimal(9)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo saldo actual para moneda {idMoneda}: {ex.Message}");
            }

            return null;
        }

        public async Task<List<SaldoDto>> ObtenerSaldoConsolidado()
        {
            var saldos = new List<SaldoDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT s.id_saldo, s.id_moneda, m.codigo_moneda, m.nombre_moneda, m.simbolo,
                                   s.fecha, s.capital_vigente_inversionistas, s.capital_colocado_sistema_financiero,
                                   s.capital_disponible, s.capital_total
                            FROM saldo_diario_fondos s
                            JOIN monedas m ON s.id_moneda = m.id_moneda
                            WHERE s.fecha = (SELECT MAX(fecha) FROM saldo_diario_fondos)
                            ORDER BY m.codigo_moneda";

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                saldos.Add(new SaldoDto
                                {
                                    IdSaldo = reader.GetInt32(0),
                                    IdMoneda = reader.GetInt32(1),
                                    CodigoMoneda = reader.GetString(2),
                                    NombreMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    Fecha = reader.GetDateTime(5),
                                    CapitalVigenteInversionistas = reader.GetDecimal(6),
                                    CapitalColocadoSistemaFinanciero = reader.GetDecimal(7),
                                    CapitalDisponible = reader.GetDecimal(8),
                                    CapitalTotal = reader.GetDecimal(9)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo saldo consolidado: {ex.Message}");
            }

            return saldos;
        }

        public async Task<List<SaldoDto>> ObtenerHistoricoMoneda(int idMoneda, int dias = 30)
        {
            var saldos = new List<SaldoDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"
                            SELECT s.id_saldo, s.id_moneda, m.codigo_moneda, m.nombre_moneda, m.simbolo,
                                   s.fecha, s.capital_vigente_inversionistas, s.capital_colocado_sistema_financiero,
                                   s.capital_disponible, s.capital_total
                            FROM saldo_diario_fondos s
                            JOIN monedas m ON s.id_moneda = m.id_moneda
                            WHERE s.id_moneda = :idMoneda
                            AND s.fecha >= TRUNC(SYSDATE) - :dias
                            ORDER BY s.fecha DESC";

                        command.Parameters.Add(new OracleParameter("idMoneda", OracleDbType.Int32) { Value = idMoneda });
                        command.Parameters.Add(new OracleParameter("dias", OracleDbType.Int32) { Value = dias });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                saldos.Add(new SaldoDto
                                {
                                    IdSaldo = reader.GetInt32(0),
                                    IdMoneda = reader.GetInt32(1),
                                    CodigoMoneda = reader.GetString(2),
                                    NombreMoneda = reader.GetString(3),
                                    Simbolo = reader.GetString(4),
                                    Fecha = reader.GetDateTime(5),
                                    CapitalVigenteInversionistas = reader.GetDecimal(6),
                                    CapitalColocadoSistemaFinanciero = reader.GetDecimal(7),
                                    CapitalDisponible = reader.GetDecimal(8),
                                    CapitalTotal = reader.GetDecimal(9)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo histórico de saldos para moneda {idMoneda}: {ex.Message}");
            }

            return saldos;
        }

        public async Task<bool> ActualizarSaldos()
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    // Obtener todas las monedas activas
                    var monedas = new List<int>();
                    using (var cmdMonedas = (OracleCommand)connection.CreateCommand())
                    {
                        cmdMonedas.CommandText = "SELECT id_moneda FROM monedas WHERE estado = 'ACTIVO'";
                        using (var reader = await cmdMonedas.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                monedas.Add(reader.GetInt32(0));
                            }
                        }
                    }

                    // Llamar al stored procedure para actualizar saldo de cada moneda
                    foreach (var idMoneda in monedas)
                    {
                        using (var cmdSP = (OracleCommand)connection.CreateCommand())
                        {
                            cmdSP.CommandText = "sp_actualizar_saldo_diario";
                            cmdSP.CommandType = CommandType.StoredProcedure;
                            cmdSP.Parameters.Add(new OracleParameter("p_id_moneda", OracleDbType.Int32) { Value = idMoneda });
                            cmdSP.Parameters.Add(new OracleParameter("p_fecha", OracleDbType.Date) { Value = DateTime.Now, Direction = ParameterDirection.Input });

                            await cmdSP.ExecuteNonQueryAsync();
                        }

                        _logger.LogInformation($"Saldo actualizado para moneda {idMoneda} usando stored procedure");
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando saldos: {ex.Message}");
                return false;
            }
        }
    }

    // ============================================================================
    // IMPLEMENTACIÓN - SERVICIO DE ROLES
    // ============================================================================

    public class RolService : IRolService
    {
        private readonly IConnectionRepository _connectionRepository;
        private readonly ILogger<RolService> _logger;

        public RolService(IConnectionRepository connectionRepository, ILogger<RolService> logger)
        {
            _connectionRepository = connectionRepository;
            _logger = logger;
        }

        public async Task<RolDto?> ObtenerPorId(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"SELECT id_rol, nombre_rol, descripcion, estado, fecha_creacion
                                               FROM roles WHERE id_rol = :id_rol";
                        command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = id });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new RolDto
                                {
                                    IdRol = reader.GetInt32(0),
                                    NombreRol = reader.GetString(1),
                                    Descripcion = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                                    Estado = reader.GetString(3),
                                    FechaCreacion = reader.GetDateTime(4)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo rol por ID: {ex.Message}");
            }

            return null;
        }

        public async Task<List<RolDto>> ObtenerTodos()
        {
            var roles = new List<RolDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"SELECT id_rol, nombre_rol, descripcion, estado, fecha_creacion
                                               FROM roles ORDER BY nombre_rol";

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                roles.Add(new RolDto
                                {
                                    IdRol = reader.GetInt32(0),
                                    NombreRol = reader.GetString(1),
                                    Descripcion = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                                    Estado = reader.GetString(3),
                                    FechaCreacion = reader.GetDateTime(4)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo roles: {ex.Message}");
            }

            return roles;
        }

        public async Task<int> Crear(RolCreateRequest request)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"INSERT INTO roles (id_rol, nombre_rol, descripcion, estado, fecha_creacion)
                                               VALUES (seq_roles.NEXTVAL, :nombre_rol, :descripcion, 'ACTIVO', SYSDATE)
                                               RETURNING id_rol INTO :id_rol";

                        command.Parameters.Add(new OracleParameter("nombre_rol", OracleDbType.Varchar2) { Value = request.NombreRol });
                        command.Parameters.Add(new OracleParameter("descripcion", OracleDbType.Varchar2) { Value = request.Descripcion });

                        var outParameter = new OracleParameter("id_rol", OracleDbType.Int32) { Direction = ParameterDirection.Output };
                        command.Parameters.Add(outParameter);

                        await command.ExecuteNonQueryAsync();

                        return Convert.ToInt32(outParameter.Value.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creando rol: {ex.Message}");
                return 0;
            }
        }

        public async Task<bool> Actualizar(int id, RolUpdateRequest request)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    var updates = new List<string>();
                    var command = (OracleCommand)connection.CreateCommand();

                    if (!string.IsNullOrEmpty(request.NombreRol))
                    {
                        updates.Add("nombre_rol = :nombre_rol");
                        command.Parameters.Add(new OracleParameter("nombre_rol", OracleDbType.Varchar2) { Value = request.NombreRol });
                    }

                    if (!string.IsNullOrEmpty(request.Descripcion))
                    {
                        updates.Add("descripcion = :descripcion");
                        command.Parameters.Add(new OracleParameter("descripcion", OracleDbType.Varchar2) { Value = request.Descripcion });
                    }

                    if (!string.IsNullOrEmpty(request.Estado))
                    {
                        updates.Add("estado = :estado");
                        command.Parameters.Add(new OracleParameter("estado", OracleDbType.Varchar2) { Value = request.Estado });
                    }

                    if (updates.Count == 0)
                    {
                        return false;
                    }

                    command.CommandText = $"UPDATE roles SET {string.Join(", ", updates)} WHERE id_rol = :id_rol";
                    command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = id });

                    var rowsAffected = await command.ExecuteNonQueryAsync();
                    return rowsAffected > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando rol: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> Eliminar(int id)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM roles WHERE id_rol = :id_rol";
                        command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = id });

                        var rowsAffected = await command.ExecuteNonQueryAsync();
                        return rowsAffected > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error eliminando rol: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> AsignarRolAUsuario(int idUsuario, int idRol, int asignadoPor)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"INSERT INTO usuarios_roles (id_usuario_rol, id_usuario, id_rol, fecha_asignacion, asignado_por)
                                               VALUES (seq_usuarios_roles.NEXTVAL, :id_usuario, :id_rol, SYSDATE, :asignado_por)";

                        command.Parameters.Add(new OracleParameter("id_usuario", OracleDbType.Int32) { Value = idUsuario });
                        command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = idRol });
                        command.Parameters.Add(new OracleParameter("asignado_por", OracleDbType.Int32) { Value = asignadoPor });

                        await command.ExecuteNonQueryAsync();
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error asignando rol a usuario: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> RemoverRolDeUsuario(int idUsuario, int idRol)
        {
            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM usuarios_roles WHERE id_usuario = :id_usuario AND id_rol = :id_rol";
                        command.Parameters.Add(new OracleParameter("id_usuario", OracleDbType.Int32) { Value = idUsuario });
                        command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = idRol });

                        var rowsAffected = await command.ExecuteNonQueryAsync();
                        return rowsAffected > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removiendo rol de usuario: {ex.Message}");
                return false;
            }
        }

        public async Task<List<UsuarioRolDto>> ObtenerRolesDeUsuario(int idUsuario)
        {
            var usuariosRoles = new List<UsuarioRolDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"SELECT ur.id_usuario_rol, ur.id_usuario, ur.id_rol,
                                                      u.usuario, r.nombre_rol, ur.fecha_asignacion,
                                                      ur.asignado_por, ua.usuario as asignado_por_nombre
                                               FROM usuarios_roles ur
                                               JOIN usuarios u ON ur.id_usuario = u.id_usuario
                                               JOIN roles r ON ur.id_rol = r.id_rol
                                               LEFT JOIN usuarios ua ON ur.asignado_por = ua.id_usuario
                                               WHERE ur.id_usuario = :id_usuario";

                        command.Parameters.Add(new OracleParameter("id_usuario", OracleDbType.Int32) { Value = idUsuario });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                usuariosRoles.Add(new UsuarioRolDto
                                {
                                    IdUsuarioRol = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdRol = reader.GetInt32(2),
                                    NombreUsuario = reader.GetString(3),
                                    NombreRol = reader.GetString(4),
                                    FechaAsignacion = reader.GetDateTime(5),
                                    AsignadoPor = reader.IsDBNull(6) ? null : reader.GetInt32(6),
                                    AsignadoPorNombre = reader.IsDBNull(7) ? null : reader.GetString(7)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo roles de usuario: {ex.Message}");
            }

            return usuariosRoles;
        }

        public async Task<List<UsuarioRolDto>> ObtenerUsuariosConRol(int idRol)
        {
            var usuariosRoles = new List<UsuarioRolDto>();

            try
            {
                using (var connection = _connectionRepository.GetConnection())
                {
                    await connection.OpenAsync();

                    using (var command = (OracleCommand)connection.CreateCommand())
                    {
                        command.CommandText = @"SELECT ur.id_usuario_rol, ur.id_usuario, ur.id_rol,
                                                      u.usuario, r.nombre_rol, ur.fecha_asignacion,
                                                      ur.asignado_por, ua.usuario as asignado_por_nombre
                                               FROM usuarios_roles ur
                                               JOIN usuarios u ON ur.id_usuario = u.id_usuario
                                               JOIN roles r ON ur.id_rol = r.id_rol
                                               LEFT JOIN usuarios ua ON ur.asignado_por = ua.id_usuario
                                               WHERE ur.id_rol = :id_rol";

                        command.Parameters.Add(new OracleParameter("id_rol", OracleDbType.Int32) { Value = idRol });

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                usuariosRoles.Add(new UsuarioRolDto
                                {
                                    IdUsuarioRol = reader.GetInt32(0),
                                    IdUsuario = reader.GetInt32(1),
                                    IdRol = reader.GetInt32(2),
                                    NombreUsuario = reader.GetString(3),
                                    NombreRol = reader.GetString(4),
                                    FechaAsignacion = reader.GetDateTime(5),
                                    AsignadoPor = reader.IsDBNull(6) ? null : reader.GetInt32(6),
                                    AsignadoPorNombre = reader.IsDBNull(7) ? null : reader.GetString(7)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo usuarios con rol: {ex.Message}");
            }

            return usuariosRoles;
        }
    }
}