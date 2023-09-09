package med.voll.api.pacientes;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import med.voll.api.direccion.DatosDireccionP;

public record DatosRegistroPaciente(

        @NotBlank
        String nombre,
        @NotBlank
        String email,
        @NotBlank
        String telefono,

        @NotBlank
        @Pattern(regexp = "\\d{4,8}")
        String documento,
        @Enumerated(EnumType.STRING)
        Seguro seguro,
        @NotNull
        @Valid
        DatosDireccionP direccionP
) {

}