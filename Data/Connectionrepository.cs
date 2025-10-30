using Oracle.ManagedDataAccess.Client;
using System.Data;

namespace BACKEND_CREDITOS.Data
{
    public interface IConnectionRepository
    {
        OracleConnection GetConnection();
        Task<bool> TestConnection();
    }

    public class ConnectionRepository : IConnectionRepository
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<ConnectionRepository> _logger;

        public ConnectionRepository(IConfiguration configuration, ILogger<ConnectionRepository> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public OracleConnection GetConnection()
        {
            var connectionString = _configuration.GetConnectionString("OracleConnection");

            if (string.IsNullOrEmpty(connectionString))
            {
                _logger.LogError("Connection string no configurada");
                throw new InvalidOperationException("Connection string 'OracleConnection' no está configurada");
            }

            return new OracleConnection(connectionString);
        }

        public async Task<bool> TestConnection()
        {
            try
            {
                using (var connection = GetConnection())
                {
                    await connection.OpenAsync();
                    _logger.LogInformation("Conexión a Oracle exitosa");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error conectando a Oracle: {ex.Message}");
                return false;
            }
        }
    }
}