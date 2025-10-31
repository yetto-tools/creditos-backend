using System.Security.Claims;
using BACKEND_CREDITOS.Models;
using BACKEND_CREDITOS.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BACKEND_CREDITOS.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // protege los endpoints con JWT
    public class InversionesController : ControllerBase
    {
        private readonly IInversionService _inversionService;
        private readonly ILogger<InversionesController> _logger;

        public InversionesController(IInversionService inversionService, ILogger<InversionesController> logger)
        {
            _inversionService = inversionService;
            _logger = logger;
        }


        /// <summary>
        /// Crear nueva inversión
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ApiResponse<int>>> Crear([FromBody] InversionCreateRequest request)
        {
            try
            {
                var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (!int.TryParse(idUsuarioString, out var idUsuario))
                {
                    return Unauthorized();
                }

                var idInversion = await _inversionService.Crear(idUsuario, request);

                if (idInversion > 0)
                {
                    return CreatedAtAction(nameof(ObtenerPorId), new { id = idInversion }, new ApiResponse<int>
                    {
                        Exitoso = true,
                        Mensaje = "Inversión creada exitosamente",
                        Datos = idInversion,
                        Codigo = 201
                    });
                }

                return BadRequest(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error al crear inversión",
                    Codigo = 400
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creando inversión");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        /// <summary>
        /// Obtener inversiones del usuario actual
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<ApiResponse<List<InversionDto>>>> ObtenerMisInversiones()
        {
            try
            {
                var idUsuarioString = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (!int.TryParse(idUsuarioString, out var idUsuario))
                {
                    return Unauthorized();
                }

                var inversiones = await _inversionService.ObtenerTodas(idUsuario);

                return Ok(new ApiResponse<List<InversionDto>>
                {
                    Exitoso = true,
                    Mensaje = $"Se obtuvieron {inversiones.Count} inversiones",
                    Datos = inversiones,
                    Codigo = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo inversiones");
                return StatusCode(500, new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error interno del servidor",
                    Codigo = 500
                });
            }
        }

        // ===========================================================
        // GET: api/inversiones/usuario/{idUsuario}
        // ===========================================================
        [HttpGet("usuario/{idUsuario}")]
        public async Task<IActionResult> ObtenerPorUsuario(int idUsuario)
        {
            try
            {
                var inversiones = await _inversionService.ObtenerTodas(idUsuario);

                if (inversiones == null || inversiones.Count == 0)
                    return NotFound(new { mensaje = $"No se encontraron inversiones para el usuario {idUsuario}" });

                return Ok(inversiones);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo inversiones: {ex.Message}");
                return StatusCode(500, new { mensaje = "Error interno del servidor" });
            }
        }

        //// ===========================================================
        //// GET: api/inversiones
        //// ===========================================================
        //[HttpGet]
        //public async Task<IActionResult> ObtenerTodas()
        //{
        //    try
        //    {
        //        var inversiones = await _inversionService.ObtenerTodas();
        //        //return Ok(inversiones);
        //        return Ok(new { exitoso = true, datos = inversiones });
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.LogError($"Error obteniendo inversiones: {ex.Message}");
        //        return StatusCode(500, new { mensaje = "Error interno del servidor" });
        //    }
        //}

        // ===========================================================
        // POST: api/inversiones/{idUsuario}
        // ===========================================================
        [HttpPost("{idUsuario}")]
        public async Task<IActionResult> Crear(int idUsuario, [FromBody] InversionCreateRequest request)
        {
            try
            {
                var id = await _inversionService.Crear(idUsuario, request);

                if (id <= 0)
                    return BadRequest(new { mensaje = "No se pudo crear la inversión" });

                return Ok(new { mensaje = "Inversión creada exitosamente", idInversion = id });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creando inversión: {ex.Message}");
                return StatusCode(500, new { mensaje = "Error interno del servidor" });
            }
        }

        // ===========================================================
        // PUT: api/inversiones/{idInversion}
        // ===========================================================
        [HttpPut("{idInversion}")]
        public async Task<IActionResult> Actualizar(int idInversion, [FromBody] InversionUpdateRequest request)
        {
            try
            {
                var actualizado = await _inversionService.Actualizar(idInversion, request);

                if (!actualizado)
                    return BadRequest(new { exitoso = false, mensaje = "No se pudo actualizar la inversión." });

                return Ok(new { exitoso = true, mensaje = "Inversión actualizada correctamente." });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error actualizando inversión: {ex.Message}");
                return StatusCode(500, new { exitoso = false, mensaje = "Error interno del servidor." });
            }
        }
        // ===========================================================
        // GET: api/inversiones/{id}
        // ===========================================================
        [HttpGet("{id}")]
        public async Task<IActionResult> ObtenerPorId(int id)
        {
            try
            {
                var inversion = await _inversionService.ObtenerPorId(id);

                if (inversion == null)
                    return NotFound(new { exitoso = false, mensaje = "Inversión no encontrada." });

                return Ok(new
                {
                    exitoso = true,
                    mensaje = "Inversión obtenida correctamente.",
                    datos = inversion
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error obteniendo inversión {id}: {ex.Message}");
                return StatusCode(500, new { exitoso = false, mensaje = "Error interno del servidor." });
            }
        }

        /// <summary>
        /// Cancelar inversión
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult<ApiResponse>> Cancelar(int id)
        {
            try
            {
                var resultado = await _inversionService.Cancelar(id);

                if (resultado)
                {
                    return Ok(new ApiResponse
                    {
                        Exitoso = true,
                        Mensaje = "Inversión cancelada",
                        Codigo = 200
                    });
                }

                return BadRequest(new ApiResponse
                {
                    Exitoso = false,
                    Mensaje = "Error al cancelar inversión",
                    Codigo = 400
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cancelando inversión");
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


