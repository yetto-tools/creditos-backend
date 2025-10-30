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

        public async Task<int> Crear(int idUsuario, InversionCreateRequest request) => 0;
        public async Task<InversionDto?> ObtenerPorId(int id) => null;
        public async Task<List<InversionDto>> ObtenerTodas(int? idUsuario = null) => new();
        public async Task<List<InversionDto>> ObtenerActivas(int? idUsuario = null) => new();
        public async Task<List<PagoInversionDto>> ObtenerPagos(int idInversion) => new();
        public async Task<bool> Cancelar(int id) => false;
        public async Task<bool> ActualizarEstados() => false;
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

        public async Task<int> Crear(int idUsuario, PrestamoCreateRequest request) => 0;
        public async Task<PrestamoDto?> ObtenerPorId(int id) => null;
        public async Task<List<PrestamoDto>> ObtenerTodas(int? idUsuario = null) => new();
        public async Task<List<PrestamoDto>> ObtenerActivos(int? idUsuario = null) => new();
        public async Task<List<PagoPrestamoDto>> ObtenerPagos(int idPrestamo) => new();
        public async Task<bool> Cancelar(int id) => false;
        public async Task<bool> ActualizarEstados() => false;
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

        public async Task<SaldoDto?> ObtenerSaldoActual(int idMoneda) => null;
        public async Task<List<SaldoDto>> ObtenerSaldoConsolidado() => new();
        public async Task<List<SaldoDto>> ObtenerHistoricoMoneda(int idMoneda, int dias = 30) => new();
        public async Task<bool> ActualizarSaldos() => false;
    }
}