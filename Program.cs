using Serilog;
using BACKEND_CREDITOS.Data;
using BACKEND_CREDITOS.Services;
using BACKEND_CREDITOS.Validators;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

// Configurar Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .WriteTo.File("logs/banco-api-{Date}.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    Log.Information("Iniciando API REST - Sistema de Operaciones Financieras Bancarias");

    var builder = WebApplication.CreateBuilder(args);

    // Agregar Serilog
    builder.Host.UseSerilog();

    // Agregar servicios de controladores
    builder.Services.AddControllers();

    // Swagger/OpenAPI
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
        {
            Title = "API - Sistema de Operaciones Financieras Bancarias",
            Version = "v1.0.0",
            Description = "API REST para gestionar inversiones y préstamos",
            Contact = new Microsoft.OpenApi.Models.OpenApiContact
            {
                Name = "Universidad Mariano Gálvez",
                Email = "kzear@miumg.edu.gt"
            }
        });

        // Agregar autenticación JWT en Swagger
        c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Ingresa el JWT token"
        });

        c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
        {
            {
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Reference = new Microsoft.OpenApi.Models.OpenApiReference
                    {
                        Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                new string[] { }
            }
        });
    });

    // Configurar CORS
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        });
    });

    // Configurar autenticación JWT
    var jwtSettings = builder.Configuration.GetSection("Jwt");
    var secretKey = jwtSettings.GetValue<string>("SecretKey") ?? "DefaultSecretKeyPorFavorCambiarEnProduccion12345";
    var issuer = jwtSettings.GetValue<string>("Issuer") ?? "BancoAPI";
    var audience = jwtSettings.GetValue<string>("Audience") ?? "BancoAPIClients";

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ClockSkew = TimeSpan.Zero
            };
        });

    // Agregar autorización
    builder.Services.AddAuthorization();

    // Validación con FluentValidation - VERSIÓN 11.9.2
    builder.Services.AddValidatorsFromAssemblyContaining<Program>();

    // Registrar servicios de la aplicación
    builder.Services.AddScoped<IConnectionRepository, ConnectionRepository>();
    builder.Services.AddScoped<IUsuarioService, UsuarioService>();
    builder.Services.AddScoped<IInversionService, InversionService>();
    builder.Services.AddScoped<IPrestamoService, PrestamoService>();
    builder.Services.AddScoped<IMonedaService, MonedaService>();
    builder.Services.AddScoped<ISaldoService, SaldoService>();
    builder.Services.AddScoped<IAuthService, AuthService>();

    // AutoMapper
    builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // Configurar IHttpClientFactory
    builder.Services.AddHttpClient();

    var app = builder.Build();

    // Configurar el pipeline HTTP
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.SwaggerEndpoint("/swagger/v1/swagger.json", "Banco API v1");
        });
    }

    app.UseHttpsRedirection();

    // Usar CORS
    app.UseCors("AllowAll");

    // Middleware de autenticación y autorización
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    // Ruta raíz
    app.MapGet("/", () => new
    {
        mensaje = "API REST - Sistema de Operaciones Financieras Bancarias",
        version = "1.0.0",
        documentacion = "/swagger"
    });

    Log.Information("API iniciada correctamente");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Error fatal en la aplicación");
}
finally
{
    Log.CloseAndFlush();
}