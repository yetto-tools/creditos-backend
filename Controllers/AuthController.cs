using System.Security.Claims;
using BACKEND_CREDITOS.Services;
using BACKEND_CREDITOS.Models;
using BACKEND_CREDITOS.Services;
using global::BACKEND_CREDITOS.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace BACKEND_CREDITOS.Controllers
{

        [ApiController]
        [Route("api/[controller]")]
        public class AuthController : ControllerBase
        {
            private readonly IAuthService _authService;
            private readonly ILogger<AuthController> _logger;

            public AuthController(IAuthService authService, ILogger<AuthController> logger)
            {
                _authService = authService;
                _logger = logger;
            }

            /// <summary>
            /// Login de usuario
            /// </summary>
            [HttpPost("login")]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse<UsuarioLoginResponse>>> Login([FromBody] UsuarioLoginRequest request)
            {
                try
                {
                    var resultado = await _authService.Login(request);

                    if (resultado != null)
                    {
                        return Ok(new ApiResponse<UsuarioLoginResponse>
                        {
                            Exitoso = true,
                            Mensaje = "Login exitoso",
                            Datos = resultado,
                            Codigo = 200
                        });
                    }

                    return Unauthorized(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Usuario o contraseña incorrectos",
                        Codigo = 401
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error en login");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Registrar nuevo usuario
            /// </summary>
            [HttpPost("registrar")]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse>> Registrar([FromBody] UsuarioRegistroRequest request)
            {
                try
                {
                    var resultado = await _authService.Registrar(request);

                    if (resultado)
                    {
                        return Ok(new ApiResponse
                        {
                            Exitoso = true,
                            Mensaje = "Usuario registrado exitosamente",
                            Codigo = 201
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al registrar usuario",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error en registro");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Cambiar contraseña
            /// </summary>
            [HttpPost("cambiar-contrasena")]
            [Authorize]
            public async Task<ActionResult<ApiResponse>> CambiarContrasena([FromBody] CambiarContrasenaRequest request)
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuario))
                    {
                        return Unauthorized();
                    }

                    var resultado = await _authService.CambiarContrasena(idUsuario, request);

                    if (resultado)
                    {
                        return Ok(new ApiResponse
                        {
                            Exitoso = true,
                            Mensaje = "Contraseña actualizada exitosamente",
                            Codigo = 200
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al actualizar contraseña",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error cambiando contraseña");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Recuperar contraseña
            /// </summary>
            [HttpPost("recuperar-contrasena")]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse>> RecuperarContrasena([FromBody] dynamic request)
            {
                try
                {
                    string usuario = request.usuario;
                    string nuevaContrasena = request.nuevaContrasena;

                    var resultado = await _authService.RecuperarContrasena(usuario, nuevaContrasena);

                    if (resultado)
                    {
                        return Ok(new ApiResponse
                        {
                            Exitoso = true,
                            Mensaje = "Contraseña recuperada exitosamente",
                            Codigo = 200
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al recuperar contraseña",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error recuperando contraseña");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }
        }

        [ApiController]
        [Route("api/[controller]")]
        [Authorize]
        public class UsuariosController : ControllerBase
        {
            private readonly IUsuarioService _usuarioService;
            private readonly ILogger<UsuariosController> _logger;

            public UsuariosController(IUsuarioService usuarioService, ILogger<UsuariosController> logger)
            {
                _usuarioService = usuarioService;
                _logger = logger;
            }

            /// <summary>
            /// Obtener perfil del usuario actual
            /// </summary>
            [HttpGet("perfil")]
            public async Task<ActionResult<ApiResponse<UsuarioDto>>> ObtenerPerfil()
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuario))
                    {
                        return Unauthorized();
                    }

                    var usuario = await _usuarioService.ObtenerPorId(idUsuario);

                    if (usuario != null)
                    {
                        return Ok(new ApiResponse<UsuarioDto>
                        {
                            Exitoso = true,
                            Mensaje = "Perfil obtenido",
                            Datos = usuario,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Usuario no encontrado",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo perfil");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener usuario por ID
            /// </summary>
            [HttpGet("{id}")]
            public async Task<ActionResult<ApiResponse<UsuarioDto>>> ObtenerPorId(int id)
            {
                try
                {
                    var usuario = await _usuarioService.ObtenerPorId(id);

                    if (usuario != null)
                    {
                        return Ok(new ApiResponse<UsuarioDto>
                        {
                            Exitoso = true,
                            Mensaje = "Usuario obtenido",
                            Datos = usuario,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Usuario no encontrado",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo usuario");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener todos los usuarios
            /// </summary>
            [HttpGet]
            public async Task<ActionResult<ApiResponse<List<UsuarioDto>>>> ObtenerTodos()
            {
                try
                {
                    var usuarios = await _usuarioService.ObtenerTodos();

                    return Ok(new ApiResponse<List<UsuarioDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {usuarios.Count} usuarios",
                        Datos = usuarios,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo usuarios");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Actualizar usuario
            /// </summary>
            [HttpPut("{id}")]
            public async Task<ActionResult<ApiResponse>> Actualizar(int id, [FromBody] UsuarioDto usuario)
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuarioAutenticado) || idUsuarioAutenticado != id)
                    {
                        return Unauthorized();
                    }

                    var resultado = await _usuarioService.Actualizar(id, usuario);

                    if (resultado)
                    {
                        return Ok(new ApiResponse
                        {
                            Exitoso = true,
                            Mensaje = "Usuario actualizado exitosamente",
                            Codigo = 200
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al actualizar usuario",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error actualizando usuario");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }
        }

        [ApiController]
        [Route("api/[controller]")]
        [Authorize]
        public class MonedasController : ControllerBase
        {
            private readonly IMonedaService _monedaService;
            private readonly ILogger<MonedasController> _logger;

            public MonedasController(IMonedaService monedaService, ILogger<MonedasController> logger)
            {
                _monedaService = monedaService;
                _logger = logger;
            }

            /// <summary>
            /// Obtener todas las monedas
            /// </summary>
            [HttpGet]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse<List<MonedaDto>>>> ObtenerTodas()
            {
                try
                {
                    var monedas = await _monedaService.ObtenerTodas();

                    return Ok(new ApiResponse<List<MonedaDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {monedas.Count} monedas",
                        Datos = monedas,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo monedas");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener moneda por ID
            /// </summary>
            [HttpGet("{id}")]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse<MonedaDto>>> ObtenerPorId(int id)
            {
                try
                {
                    var moneda = await _monedaService.ObtenerPorId(id);

                    if (moneda != null)
                    {
                        return Ok(new ApiResponse<MonedaDto>
                        {
                            Exitoso = true,
                            Mensaje = "Moneda obtenida",
                            Datos = moneda,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Moneda no encontrada",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo moneda");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener moneda por código
            /// </summary>
            [HttpGet("codigo/{codigo}")]
            [AllowAnonymous]
            public async Task<ActionResult<ApiResponse<MonedaDto>>> ObtenerPorCodigo(string codigo)
            {
                try
                {
                    var moneda = await _monedaService.ObtenerPorCodigo(codigo);

                    if (moneda != null)
                    {
                        return Ok(new ApiResponse<MonedaDto>
                        {
                            Exitoso = true,
                            Mensaje = "Moneda obtenida",
                            Datos = moneda,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Moneda no encontrada",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo moneda");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }
        }

        //[ApiController]
        //[Route("api/[controller]")]
        //[Authorize]
        //public class InversionesController : ControllerBase
        //{
        //    private readonly IInversionService _inversionService;
        //    private readonly ILogger<InversionesController> _logger;

        //    public InversionesController(IInversionService inversionService, ILogger<InversionesController> logger)
        //    {
        //        _inversionService = inversionService;
        //        _logger = logger;
        //    }

        //    /// <summary>
        //    /// Crear nueva inversión
        //    /// </summary>
        //    [HttpPost]
        //    public async Task<ActionResult<ApiResponse<int>>> Crear([FromBody] InversionCreateRequest request)
        //    {
        //        try
        //        {
        //            var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        //            if (!int.TryParse(idUsuarioString, out var idUsuario))
        //            {
        //                return Unauthorized();
        //            }

        //            var idInversion = await _inversionService.Crear(idUsuario, request);

        //            if (idInversion > 0)
        //            {
        //                return CreatedAtAction(nameof(ObtenerPorId), new { id = idInversion }, new ApiResponse<int>
        //                {
        //                    Exitoso = true,
        //                    Mensaje = "Inversión creada exitosamente",
        //                    Datos = idInversion,
        //                    Codigo = 201
        //                });
        //            }

        //            return BadRequest(new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error al crear inversión",
        //                Codigo = 400
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error creando inversión");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Obtener inversión por ID
        //    /// </summary>
        //    [HttpGet("{id}")]
        //    public async Task<ActionResult<ApiResponse<InversionDto>>> ObtenerPorId(int id)
        //    {
        //        try
        //        {
        //            var inversion = await _inversionService.ObtenerPorId(id);

        //            if (inversion != null)
        //            {
        //                return Ok(new ApiResponse<InversionDto>
        //                {
        //                    Exitoso = true,
        //                    Mensaje = "Inversión obtenida",
        //                    Datos = inversion,
        //                    Codigo = 200
        //                });
        //            }

        //            return NotFound(new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Inversión no encontrada",
        //                Codigo = 404
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error obteniendo inversión");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Obtener inversiones del usuario actual
        //    /// </summary>
        //    [HttpGet]
        //    public async Task<ActionResult<ApiResponse<List<InversionDto>>>> ObtenerMisInversiones()
        //    {
        //        try
        //        {
        //            var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        //            if (!int.TryParse(idUsuarioString, out var idUsuario))
        //            {
        //                return Unauthorized();
        //            }

        //            var inversiones = await _inversionService.ObtenerTodas(idUsuario);

        //            return Ok(new ApiResponse<List<InversionDto>>
        //            {
        //                Exitoso = true,
        //                Mensaje = $"Se obtuvieron {inversiones.Count} inversiones",
        //                Datos = inversiones,
        //                Codigo = 200
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error obteniendo inversiones");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Obtener inversiones de un usuario específico
        //    /// </summary>
        //    [HttpGet("usuario/{idUsuario}")]
        //    public async Task<ActionResult<ApiResponse<List<InversionDto>>>> ObtenerInversionesUsuario(int idUsuario)
        //    {
        //        try
        //        {
        //            var inversiones = await _inversionService.ObtenerTodas(idUsuario);

        //            return Ok(new ApiResponse<List<InversionDto>>
        //            {
        //                Exitoso = true,
        //                Mensaje = $"Se obtuvieron {inversiones.Count} inversiones",
        //                Datos = inversiones,
        //                Codigo = 200
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error obteniendo inversiones del usuario");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Obtener inversiones activas del usuario
        //    /// </summary>
        //    [HttpGet("activas")]
        //    public async Task<ActionResult<ApiResponse<List<InversionDto>>>> ObtenerActivas()
        //    {
        //        try
        //        {
        //            var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        //            if (!int.TryParse(idUsuarioString, out var idUsuario))
        //            {
        //                return Unauthorized();
        //            }

        //            var inversiones = await _inversionService.ObtenerActivas(idUsuario);

        //            return Ok(new ApiResponse<List<InversionDto>>
        //            {
        //                Exitoso = true,
        //                Mensaje = $"Se obtuvieron {inversiones.Count} inversiones activas",
        //                Datos = inversiones,
        //                Codigo = 200
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error obteniendo inversiones activas");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Obtener pagos de una inversión
        //    /// </summary>
        //    [HttpGet("{id}/pagos")]
        //    public async Task<ActionResult<ApiResponse<List<PagoInversionDto>>>> ObtenerPagos(int id)
        //    {
        //        try
        //        {
        //            var pagos = await _inversionService.ObtenerPagos(id);

        //            return Ok(new ApiResponse<List<PagoInversionDto>>
        //            {
        //                Exitoso = true,
        //                Mensaje = $"Se obtuvieron {pagos.Count} pagos",
        //                Datos = pagos,
        //                Codigo = 200
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error obteniendo pagos");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }

        //    /// <summary>
        //    /// Cancelar inversión
        //    /// </summary>
        //    [HttpDelete("{id}")]
        //    public async Task<ActionResult<ApiResponse>> Cancelar(int id)
        //    {
        //        try
        //        {
        //            var resultado = await _inversionService.Cancelar(id);

        //            if (resultado)
        //            {
        //                return Ok(new ApiResponse
        //                {
        //                    Exitoso = true,
        //                    Mensaje = "Inversión cancelada",
        //                    Codigo = 200
        //                });
        //            }

        //            return BadRequest(new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error al cancelar inversión",
        //                Codigo = 400
        //            });
        //        }
        //        catch (Exception ex)
        //        {
        //            _logger.LogError(ex, "Error cancelando inversión");
        //            return StatusCode(500, new ApiResponse
        //            {
        //                Exitoso = false,
        //                Mensaje = "Error interno del servidor",
        //                Codigo = 500
        //            });
        //        }
        //    }
        //}

        [ApiController]
        [Route("api/[controller]")]
        [Authorize]
        public class PrestamosController : ControllerBase
        {
            private readonly IPrestamoService _prestamoService;
            private readonly ILogger<PrestamosController> _logger;

            public PrestamosController(IPrestamoService prestamoService, ILogger<PrestamosController> logger)
            {
                _prestamoService = prestamoService;
                _logger = logger;
            }

            /// <summary>
            /// Crear nuevo préstamo
            /// </summary>
            [HttpPost]
            public async Task<ActionResult<ApiResponse<int>>> Crear([FromBody] PrestamoCreateRequest request)
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuario))
                    {
                        return Unauthorized();
                    }

                    var idPrestamo = await _prestamoService.Crear(idUsuario, request);

                    if (idPrestamo > 0)
                    {
                        return CreatedAtAction(nameof(ObtenerPorId), new { id = idPrestamo }, new ApiResponse<int>
                        {
                            Exitoso = true,
                            Mensaje = "Préstamo creado exitosamente",
                            Datos = idPrestamo,
                            Codigo = 201
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al crear préstamo",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error creando préstamo");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener préstamo por ID
            /// </summary>
            [HttpGet("{id}")]
            public async Task<ActionResult<ApiResponse<PrestamoDto>>> ObtenerPorId(int id)
            {
                try
                {
                    var prestamo = await _prestamoService.ObtenerPorId(id);

                    if (prestamo != null)
                    {
                        return Ok(new ApiResponse<PrestamoDto>
                        {
                            Exitoso = true,
                            Mensaje = "Préstamo obtenido",
                            Datos = prestamo,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Préstamo no encontrado",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo préstamo");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener préstamos del usuario
            /// </summary>
            [HttpGet]
            public async Task<ActionResult<ApiResponse<List<PrestamoDto>>>> ObtenerMisPrestamos()
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuario))
                    {
                        return Unauthorized();
                    }

                    var prestamos = await _prestamoService.ObtenerTodas(idUsuario);

                    return Ok(new ApiResponse<List<PrestamoDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {prestamos.Count} préstamos",
                        Datos = prestamos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo préstamos");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener préstamos de un usuario específico
            /// </summary>
            [HttpGet("usuario/{idUsuario}")]
            public async Task<ActionResult<ApiResponse<List<PrestamoDto>>>> ObtenerPrestamosUsuario(int idUsuario)
            {
                try
                {
                    var prestamos = await _prestamoService.ObtenerTodas(idUsuario);

                    return Ok(new ApiResponse<List<PrestamoDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {prestamos.Count} préstamos",
                        Datos = prestamos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo préstamos del usuario");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener préstamos activos
            /// </summary>
            [HttpGet("activos")]
            public async Task<ActionResult<ApiResponse<List<PrestamoDto>>>> ObtenerActivos()
            {
                try
                {
                    var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!int.TryParse(idUsuarioString, out var idUsuario))
                    {
                        return Unauthorized();
                    }

                    var prestamos = await _prestamoService.ObtenerActivos(idUsuario);

                    return Ok(new ApiResponse<List<PrestamoDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {prestamos.Count} préstamos activos",
                        Datos = prestamos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo préstamos activos");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener pagos de un préstamo
            /// </summary>
            [HttpGet("{id}/pagos")]
            public async Task<ActionResult<ApiResponse<List<PagoPrestamoDto>>>> ObtenerPagos(int id)
            {
                try
                {
                    var pagos = await _prestamoService.ObtenerPagos(id);

                    return Ok(new ApiResponse<List<PagoPrestamoDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {pagos.Count} pagos",
                        Datos = pagos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo pagos");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Cancelar préstamo
            /// </summary>
            [HttpDelete("{id}")]
            public async Task<ActionResult<ApiResponse>> Cancelar(int id)
            {
                try
                {
                    var resultado = await _prestamoService.Cancelar(id);

                    if (resultado)
                    {
                        return Ok(new ApiResponse
                        {
                            Exitoso = true,
                            Mensaje = "Préstamo cancelado",
                            Codigo = 200
                        });
                    }

                    return BadRequest(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error al cancelar préstamo",
                        Codigo = 400
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error cancelando préstamo");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }
        }

        [ApiController]
        [Route("api/[controller]")]
        [Authorize]
        public class SaldoController : ControllerBase
        {
            private readonly ISaldoService _saldoService;
            private readonly ILogger<SaldoController> _logger;

            public SaldoController(ISaldoService saldoService, ILogger<SaldoController> logger)
            {
                _saldoService = saldoService;
                _logger = logger;
            }

            /// <summary>
            /// Obtener saldo consolidado
            /// </summary>
            [HttpGet]
            public async Task<ActionResult<ApiResponse<List<SaldoDto>>>> ObtenerSaldoConsolidado()
            {
                try
                {
                    var saldos = await _saldoService.ObtenerSaldoConsolidado();

                    return Ok(new ApiResponse<List<SaldoDto>>
                    {
                        Exitoso = true,
                        Mensaje = "Saldo consolidado obtenido",
                        Datos = saldos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo saldo");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener saldo de un usuario específico
            /// </summary>
            [HttpGet("usuario/{idUsuario}")]
            public async Task<ActionResult<ApiResponse<List<SaldoUsuarioDto>>>> ObtenerSaldoUsuario(int idUsuario)
            {
                try
                {
                    var saldos = await _saldoService.ObtenerSaldoPorUsuario(idUsuario);

                    return Ok(new ApiResponse<List<SaldoUsuarioDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Saldo de usuario obtenido",
                        Datos = saldos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo saldo del usuario");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener saldo actual de una moneda
            /// </summary>
            [HttpGet("moneda/{idMoneda}")]
            public async Task<ActionResult<ApiResponse<SaldoDto>>> ObtenerSaldoMoneda(int idMoneda)
            {
                try
                {
                    var saldo = await _saldoService.ObtenerSaldoActual(idMoneda);

                    if (saldo != null)
                    {
                        return Ok(new ApiResponse<SaldoDto>
                        {
                            Exitoso = true,
                            Mensaje = "Saldo obtenido",
                            Datos = saldo,
                            Codigo = 200
                        });
                    }

                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Saldo no encontrado",
                        Codigo = 404
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo saldo");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }

            /// <summary>
            /// Obtener histórico de saldo
            /// </summary>
            [HttpGet("historico/{idMoneda}")]
            public async Task<ActionResult<ApiResponse<List<SaldoDto>>>> ObtenerHistorico(int idMoneda, [FromQuery] int dias = 30)
            {
                try
                {
                    var saldos = await _saldoService.ObtenerHistoricoMoneda(idMoneda, dias);

                    return Ok(new ApiResponse<List<SaldoDto>>
                    {
                        Exitoso = true,
                        Mensaje = $"Se obtuvieron {saldos.Count} registros",
                        Datos = saldos,
                        Codigo = 200
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error obteniendo histórico");
                    return StatusCode(500, new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Error interno del servidor",
                        Codigo = 500
                    });
                }
            }
        }

}
