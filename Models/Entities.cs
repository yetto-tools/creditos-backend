namespace BACKEND_CREDITOS.Models
{
    // ============================================================================
    // MODELOS DE DOMINIO - ENTIDADES
    // ============================================================================

    public class Usuario
    {
        public int IdUsuario { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string Contrasena { get; set; } = string.Empty;
        public string NombreCompleto { get; set; } = string.Empty;
        public string CorreoElectronico { get; set; } = string.Empty;
        public string Estado { get; set; } = "ACTIVO";
        public DateTime FechaCreacion { get; set; }
        public DateTime? FechaUltimoAcceso { get; set; }
        public DateTime FechaCambioContrasena { get; set; }

        // Navegación
        public List<UsuarioRol> UsuariosRoles { get; set; } = new();
    }

    public class Rol
    {
        public int IdRol { get; set; }
        public string NombreRol { get; set; } = string.Empty;
        public string Descripcion { get; set; } = string.Empty;
        public string Estado { get; set; } = "ACTIVO";
        public DateTime FechaCreacion { get; set; }

        // Navegación
        public List<UsuarioRol> UsuariosRoles { get; set; } = new();
    }

    public class UsuarioRol
    {
        public int IdUsuarioRol { get; set; }
        public int IdUsuario { get; set; }
        public int IdRol { get; set; }
        public DateTime FechaAsignacion { get; set; }
        public int? AsignadoPor { get; set; }

        // Navegación
        public Usuario? Usuario { get; set; }
        public Rol? Rol { get; set; }
        public Usuario? AsignadoPorUsuario { get; set; }
    }

    public class Moneda
    {
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string NombreMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public string Estado { get; set; } = "ACTIVO";
    }

    public class Inversion
    {
        public int IdInversion { get; set; }
        public int IdUsuario { get; set; }
        public int IdMoneda { get; set; }
        public decimal CapitalInicial { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty; // MENSUAL o FINAL
        public DateTime FechaInicio { get; set; }
        public DateTime FechaVencimiento { get; set; }
        public decimal InteresTotalProyectado { get; set; }
        public decimal MontoTotalARecibir { get; set; }
        public string Estado { get; set; } = "VIGENTE";
        public DateTime FechaCreacion { get; set; }
        public string Observaciones { get; set; } = string.Empty;

        // Navegación
        public Usuario? Usuario { get; set; }
        public Moneda? Moneda { get; set; }
        public List<PagoInversion> Pagos { get; set; } = new();
    }
    public class InversionUpdateRequest
    {
        public int IdMoneda { get; set; }
        public decimal CapitalInicial { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = "MENSUAL";
        public string? Observaciones { get; set; }
        public string? Estado { get; set; } = "VIGENTE";
    }


    public class PagoInversion
    {
        public int IdPagoInversion { get; set; }
        public int IdInversion { get; set; }
        public int NumeroPago { get; set; }
        public decimal CapitalPagado { get; set; }
        public decimal InteresPagado { get; set; }
        public decimal MontoTotalPagado { get; set; }
        public DateTime? FechaPago { get; set; }
        public DateTime FechaProgramada { get; set; }
        public string EstadoPago { get; set; } = "PENDIENTE";
        public DateTime FechaCreacion { get; set; }

        // Navegación
        public Inversion? Inversion { get; set; }
    }

    public class Prestamo
    {
        public int IdPrestamo { get; set; }
        public int IdUsuario { get; set; }
        public int IdMoneda { get; set; }
        public string EntidadFinanciera { get; set; } = string.Empty;
        public decimal CapitalPrestado { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty;
        public DateTime FechaInicio { get; set; }
        public DateTime FechaVencimiento { get; set; }
        public decimal InteresTotalProyectado { get; set; }
        public decimal MontoTotalARecibir { get; set; }
        public string Estado { get; set; } = "VIGENTE";
        public DateTime FechaCreacion { get; set; }
        public string Observaciones { get; set; } = string.Empty;

        // Navegación
        public Usuario? Usuario { get; set; }
        public Moneda? Moneda { get; set; }
        public List<PagoPrestamo> Pagos { get; set; } = new();
    }

    public class PagoPrestamo
    {
        public int IdPagoPrestamo { get; set; }
        public int IdPrestamo { get; set; }
        public int NumeroPago { get; set; }
        public decimal CapitalPagado { get; set; }
        public decimal InteresPagado { get; set; }
        public decimal MontoTotalPagado { get; set; }
        public DateTime? FechaPago { get; set; }
        public DateTime FechaProgramada { get; set; }
        public string EstadoPago { get; set; } = "PENDIENTE";
        public DateTime FechaCreacion { get; set; }

        // Navegación
        public Prestamo? Prestamo { get; set; }
    }

    public class SaldoDiarioFondos
    {
        public int IdSaldo { get; set; }
        public int IdMoneda { get; set; }
        public DateTime Fecha { get; set; }
        public decimal CapitalVigenteInversionistas { get; set; }
        public decimal CapitalColocadoSistemaFinanciero { get; set; }
        public decimal CapitalDisponible { get; set; }
        public decimal CapitalTotal { get; set; }
        public DateTime FechaCreacion { get; set; }

        // Navegación
        public Moneda? Moneda { get; set; }
    }

    // ============================================================================
    // DTOs - DATA TRANSFER OBJECTS
    // ============================================================================

    // Usuario DTOs
    public class UsuarioLoginRequest
    {
        public string Usuario { get; set; } = string.Empty;
        public string Contrasena { get; set; } = string.Empty;
    }

    public class UsuarioLoginResponse
    {
        public int IdUsuario { get; set; }
        public string Usuario { get; set; } = string.Empty;
        public string NombreCompleto { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public DateTime TokenExpiration { get; set; }
    }

    public class UsuarioRegistroRequest
    {
        public string Usuario { get; set; } = string.Empty;
        public string Contrasena { get; set; } = string.Empty;
        public string ConfirmarContrasena { get; set; } = string.Empty;
        public string NombreCompleto { get; set; } = string.Empty;
        public string CorreoElectronico { get; set; } = string.Empty;
    }

    public class UsuarioDto
    {
        public int IdUsuario { get; set; }
        public string Usuario { get; set; } = string.Empty;
        public string NombreCompleto { get; set; } = string.Empty;
        public string CorreoElectronico { get; set; } = string.Empty;
        public string Estado { get; set; } = string.Empty;
        public DateTime FechaCreacion { get; set; }
        public DateTime? FechaUltimoAcceso { get; set; }
    }

    public class CambiarContrasenaRequest
    {
        public string ContrasenaActual { get; set; } = string.Empty;
        public string ContrasenaNueva { get; set; } = string.Empty;
        public string ConfirmarContrasenaNueva { get; set; } = string.Empty;
    }

    // Rol DTOs
    public class RolDto
    {
        public int IdRol { get; set; }
        public string NombreRol { get; set; } = string.Empty;
        public string Descripcion { get; set; } = string.Empty;
        public string Estado { get; set; } = string.Empty;
        public DateTime FechaCreacion { get; set; }
    }

    public class RolCreateRequest
    {
        public string NombreRol { get; set; } = string.Empty;
        public string Descripcion { get; set; } = string.Empty;
    }

    public class RolUpdateRequest
    {
        public string? NombreRol { get; set; }
        public string? Descripcion { get; set; }
        public string? Estado { get; set; }
    }

    public class UsuarioRolDto
    {
        public int IdUsuarioRol { get; set; }
        public int IdUsuario { get; set; }
        public int IdRol { get; set; }
        public string NombreUsuario { get; set; } = string.Empty;
        public string NombreRol { get; set; } = string.Empty;
        public DateTime FechaAsignacion { get; set; }
        public int? AsignadoPor { get; set; }
        public string? AsignadoPorNombre { get; set; }
    }

    public class AsignarRolRequest
    {
        public int IdUsuario { get; set; }
        public int IdRol { get; set; }
    }

    // Moneda DTOs
    public class MonedaDto
    {
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string NombreMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public string Estado { get; set; } = string.Empty;
    }

    // Inversion DTOs
    public class InversionCreateRequest
    {
        public int IdMoneda { get; set; }
        public decimal CapitalInicial { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty; // MENSUAL o FINAL
        public string? Observaciones { get; set; } = string.Empty;
    }

    public class InversionDto
    {
        public int IdInversion { get; set; }
        public int IdUsuario { get; set; }
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public decimal CapitalInicial { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty;
        public DateTime FechaInicio { get; set; }
        public DateTime FechaVencimiento { get; set; }
        public decimal InteresTotalProyectado { get; set; }
        public decimal MontoTotalARecibir { get; set; }
        public string Estado { get; set; } = string.Empty;
        public int DiasRestantes { get; set; }
        public List<PagoInversionDto> Pagos { get; set; } = new();
    }

    public class PagoInversionDto
    {
        public int IdPagoInversion { get; set; }
        public int NumeroPago { get; set; }
        public decimal CapitalPagado { get; set; }
        public decimal InteresPagado { get; set; }
        public decimal MontoTotalPagado { get; set; }
        public DateTime FechaProgramada { get; set; }
        public DateTime? FechaPago { get; set; }
        public string EstadoPago { get; set; } = string.Empty;
    }

    // Prestamo DTOs
    public class PrestamoCreateRequest
    {
        public int IdMoneda { get; set; }
        public string EntidadFinanciera { get; set; } = string.Empty;
        public decimal CapitalPrestado { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty;
        public string Observaciones { get; set; } = string.Empty;
    }

    public class PrestamoDto
    {
        public int IdPrestamo { get; set; }
        public int IdUsuario { get; set; }
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public string EntidadFinanciera { get; set; } = string.Empty;
        public decimal CapitalPrestado { get; set; }
        public decimal TasaInteres { get; set; }
        public int PlazoDias { get; set; }
        public string ModalidadPago { get; set; } = string.Empty;
        public DateTime FechaInicio { get; set; }
        public DateTime FechaVencimiento { get; set; }
        public decimal InteresTotalProyectado { get; set; }
        public decimal MontoTotalARecibir { get; set; }
        public string Estado { get; set; } = string.Empty;
        public int DiasRestantes { get; set; }
        public List<PagoPrestamoDto> Pagos { get; set; } = new();
    }

    public class PagoPrestamoDto
    {
        public int IdPagoPrestamo { get; set; }
        public int NumeroPago { get; set; }
        public decimal CapitalPagado { get; set; }
        public decimal InteresPagado { get; set; }
        public decimal MontoTotalPagado { get; set; }
        public DateTime FechaProgramada { get; set; }
        public DateTime? FechaPago { get; set; }
        public string EstadoPago { get; set; } = string.Empty;
    }

    // Saldo DTOs
    public class SaldoDto
    {
        public int IdSaldo { get; set; }
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string NombreMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public DateTime Fecha { get; set; }
        public decimal CapitalVigenteInversionistas { get; set; }
        public decimal CapitalColocadoSistemaFinanciero { get; set; }
        public decimal CapitalDisponible { get; set; }
        public decimal CapitalTotal { get; set; }
    }

    public class SaldoUsuarioDto
    {
        public int IdUsuario { get; set; }
        public int IdMoneda { get; set; }
        public string CodigoMoneda { get; set; } = string.Empty;
        public string Simbolo { get; set; } = string.Empty;
        public decimal CapitalInvertido { get; set; }
        public decimal CapitalEnPrestamos { get; set; }
        public decimal BalanceNeto { get; set; }
    }

    // Respuestas genéricas
    public class ApiResponse<T>
    {
        public bool Exitoso { get; set; }
        public string Mensaje { get; set; } = string.Empty;
        public T? Datos { get; set; }
        public int Codigo { get; set; }
    }

    public class ApiResponse
    {
        public bool Exitoso { get; set; }
        public string Mensaje { get; set; } = string.Empty;
        public int Codigo { get; set; }
    }

    public class PaginatedResponse<T>
    {
        public List<T> Items { get; set; } = new();
        public int TotalItems { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
    }
}