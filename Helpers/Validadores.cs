using BACKEND_CREDITOS.Models;
using FluentValidation;

namespace BACKEND_CREDITOS.Validators
{
    public class UsuarioLoginRequestValidator : AbstractValidator<UsuarioLoginRequest>
    {
        public UsuarioLoginRequestValidator()
        {
            RuleFor(x => x.Usuario)
                .NotEmpty().WithMessage("El usuario es requerido")
                .MinimumLength(3).WithMessage("El usuario debe tener al menos 3 caracteres");

            RuleFor(x => x.Contrasena)
                .NotEmpty().WithMessage("La contraseña es requerida")
                .MinimumLength(6).WithMessage("La contraseña debe tener al menos 6 caracteres");
        }
    }

    public class UsuarioRegistroRequestValidator : AbstractValidator<UsuarioRegistroRequest>
    {
        public UsuarioRegistroRequestValidator()
        {
            RuleFor(x => x.Usuario)
                .NotEmpty().WithMessage("El usuario es requerido")
                .MinimumLength(3).WithMessage("El usuario debe tener al menos 3 caracteres")
                .MaximumLength(50).WithMessage("El usuario no puede exceder 50 caracteres");

            RuleFor(x => x.Contrasena)
                .NotEmpty().WithMessage("La contraseña es requerida")
                .MinimumLength(6).WithMessage("La contraseña debe tener al menos 6 caracteres");

            RuleFor(x => x.ConfirmarContrasena)
                .Equal(x => x.Contrasena).WithMessage("Las contraseñas no coinciden");

            RuleFor(x => x.NombreCompleto)
                .NotEmpty().WithMessage("El nombre completo es requerido")
                .MaximumLength(100).WithMessage("El nombre no puede exceder 100 caracteres");

            RuleFor(x => x.CorreoElectronico)
                .EmailAddress().WithMessage("El correo electrónico no es válido")
                .When(x => !string.IsNullOrEmpty(x.CorreoElectronico));
        }
    }

    public class CambiarContrasenaRequestValidator : AbstractValidator<CambiarContrasenaRequest>
    {
        public CambiarContrasenaRequestValidator()
        {
            RuleFor(x => x.ContrasenaActual)
                .NotEmpty().WithMessage("La contraseña actual es requerida");

            RuleFor(x => x.ContrasenaNueva)
                .NotEmpty().WithMessage("La contraseña nueva es requerida")
                .MinimumLength(6).WithMessage("La contraseña debe tener al menos 6 caracteres");

            RuleFor(x => x.ConfirmarContrasenaNueva)
                .Equal(x => x.ContrasenaNueva).WithMessage("Las contraseñas no coinciden");
        }
    }

    public class InversionCreateRequestValidator : AbstractValidator<InversionCreateRequest>
    {
        public InversionCreateRequestValidator()
        {
            RuleFor(x => x.IdMoneda)
                .GreaterThan(0).WithMessage("Debe seleccionar una moneda");

            RuleFor(x => x.CapitalInicial)
                .GreaterThan(0).WithMessage("El capital debe ser mayor a 0");

            RuleFor(x => x.TasaInteres)
                .GreaterThan(0).WithMessage("La tasa de interés debe ser mayor a 0")
                .LessThanOrEqualTo(100).WithMessage("La tasa de interés no puede exceder 100");

            RuleFor(x => x.PlazoDias)
                .GreaterThan(0).WithMessage("El plazo debe ser mayor a 0")
                .LessThanOrEqualTo(3650).WithMessage("El plazo no puede exceder 10 años");

            RuleFor(x => x.ModalidadPago)
                .NotEmpty().WithMessage("La modalidad de pago es requerida")
                .Must(x => x == "MENSUAL" || x == "FINAL").WithMessage("La modalidad debe ser MENSUAL o FINAL");
        }
    }

    public class PrestamoCreateRequestValidator : AbstractValidator<PrestamoCreateRequest>
    {
        public PrestamoCreateRequestValidator()
        {
            RuleFor(x => x.IdMoneda)
                .GreaterThan(0).WithMessage("Debe seleccionar una moneda");

            RuleFor(x => x.EntidadFinanciera)
                .NotEmpty().WithMessage("La entidad financiera es requerida")
                .MaximumLength(100).WithMessage("El nombre no puede exceder 100 caracteres");

            RuleFor(x => x.CapitalPrestado)
                .GreaterThan(0).WithMessage("El capital debe ser mayor a 0");

            RuleFor(x => x.TasaInteres)
                .GreaterThan(0).WithMessage("La tasa de interés debe ser mayor a 0")
                .LessThanOrEqualTo(100).WithMessage("La tasa de interés no puede exceder 100");

            RuleFor(x => x.PlazoDias)
                .GreaterThan(0).WithMessage("El plazo debe ser mayor a 0")
                .LessThanOrEqualTo(3650).WithMessage("El plazo no puede exceder 10 años");

            RuleFor(x => x.ModalidadPago)
                .NotEmpty().WithMessage("La modalidad de pago es requerida")
                .Must(x => x == "MENSUAL" || x == "FINAL").WithMessage("La modalidad debe ser MENSUAL o FINAL");
        }
    }


}
