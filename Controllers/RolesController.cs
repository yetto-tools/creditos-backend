using System.Security.Claims;
using BACKEND_CREDITOS.Services;
using BACKEND_CREDITOS.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BACKEND_CREDITOS.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class RolesController : ControllerBase
    {
        private readonly IRolService _rolService;
        private readonly ILogger<RolesController> _logger;

        public RolesController(IRolService rolService, ILogger<RolesController> logger)
        {
            _rolService = rolService;
            _logger = logger;
        }

        /// <summary>
        /// Obtener todos los roles
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<List<RolDto>>>> ObtenerTodos()
        {
            try
            {
                var roles = await _rolService.ObtenerTodos();

                return Ok(new ApiResponse<List<RolDto>>
                {
                    Exitoso = true,
                    Mensaje = "Roles obtenidos exitosamente",
                    Datos = roles,
                    Codigo = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo roles");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Obtener rol por ID
        /// </summary>
        [HttpGet("{id}")]
        public async Task<ActionResult<ApiResponse<RolDto>>> ObtenerPorId(int id)
        {
            try
            {
                var rol = await _rolService.ObtenerPorId(id);

                if (rol == null)
                {
                    return NotFound(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Rol no encontrado",
                        Codigo = 404
                    });
                }

                return Ok(new ApiResponse<RolDto>
                {
                    Exitoso = true,
                    Mensaje = "Rol obtenido exitosamente",
                    Datos = rol,
                    Codigo = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo rol por ID");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Crear nuevo rol
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ApiResponse<int>>> Crear([FromBody] RolCreateRequest request)
        {
            try
            {
                var idRol = await _rolService.Crear(request);

                if (idRol > 0)
                {
                    return Ok(new ApiResponse<int>
                    {
                        Exitoso = true,
                        Mensaje = "Rol creado exitosamente",
                        Datos = idRol,
                        Codigo = 201
                    });
                }

                return BadRequest(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "No se pudo crear el rol",
                    Codigo = 400
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando rol");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Actualizar rol
        /// </summary>
        [HttpPut("{id}")]
        public async Task<ActionResult<ApiResponse>> Actualizar(int id, [FromBody] RolUpdateRequest request)
        {
            try
            {
                var resultado = await _rolService.Actualizar(id, request);

                if (resultado)
                {
                    return Ok(new ApiResponse
                    {
                        Exitoso = true,
                        Mensaje = "Rol actualizado exitosamente",
                        Codigo = 200
                    });
                }

                return NotFound(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Rol no encontrado o sin cambios",
                    Codigo = 404
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando rol");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Eliminar rol
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult<ApiResponse>> Eliminar(int id)
        {
            try
            {
                var resultado = await _rolService.Eliminar(id);

                if (resultado)
                {
                    return Ok(new ApiResponse
                    {
                        Exitoso = true,
                        Mensaje = "Rol eliminado exitosamente",
                        Codigo = 200
                    });
                }

                return NotFound(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Rol no encontrado",
                    Codigo = 404
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error eliminando rol");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Asignar rol a usuario
        /// </summary>
        [HttpPost("asignar")]
        public async Task<ActionResult<ApiResponse>> AsignarRol([FromBody] AsignarRolRequest request)
        {
            try
            {
                // Obtener el ID del usuario actual desde el token JWT
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out int asignadoPor))
                {
                    return Unauthorized(new ApiResponse
                    {
                        Exitoso = false,
                        Mensaje = "Usuario no autenticado",
                        Codigo = 401
                    });
                }

                var resultado = await _rolService.AsignarRolAUsuario(request.IdUsuario, request.IdRol, asignadoPor);

                if (resultado)
                {
                    return Ok(new ApiResponse
                    {
                        Exitoso = true,
                        Mensaje = "Rol asignado exitosamente",
                        Codigo = 200
                    });
                }

                return BadRequest(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "No se pudo asignar el rol. Puede que ya esté asignado o los IDs no sean válidos",
                    Codigo = 400
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error asignando rol");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Remover rol de usuario
        /// </summary>
        [HttpDelete("remover")]
        public async Task<ActionResult<ApiResponse>> RemoverRol([FromBody] AsignarRolRequest request)
        {
            try
            {
                var resultado = await _rolService.RemoverRolDeUsuario(request.IdUsuario, request.IdRol);

                if (resultado)
                {
                    return Ok(new ApiResponse
                    {
                        Exitoso = true,
                        Mensaje = "Rol removido exitosamente",
                        Codigo = 200
                    });
                }

                return NotFound(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Asignación de rol no encontrada",
                    Codigo = 404
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removiendo rol");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Obtener roles de un usuario
        /// </summary>
        [HttpGet("usuario/{idUsuario}")]
        public async Task<ActionResult<ApiResponse<List<UsuarioRolDto>>>> ObtenerRolesDeUsuario(int idUsuario)
        {
            try
            {
                var roles = await _rolService.ObtenerRolesDeUsuario(idUsuario);

                return Ok(new ApiResponse<List<UsuarioRolDto>>
                {
                    Exitoso = true,
                    Mensaje = "Roles de usuario obtenidos exitosamente",
                    Datos = roles,
                    Codigo = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo roles de usuario");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Obtener usuarios con un rol específico
        /// </summary>
        [HttpGet("{idRol}/usuarios")]
        public async Task<ActionResult<ApiResponse<List<UsuarioRolDto>>>> ObtenerUsuariosConRol(int idRol)
        {
            try
            {
                var usuarios = await _rolService.ObtenerUsuariosConRol(idRol);

                return Ok(new ApiResponse<List<UsuarioRolDto>>
                {
                    Exitoso = true,
                    Mensaje = "Usuarios con rol obtenidos exitosamente",
                    Datos = usuarios,
                    Codigo = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo usuarios con rol");
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
