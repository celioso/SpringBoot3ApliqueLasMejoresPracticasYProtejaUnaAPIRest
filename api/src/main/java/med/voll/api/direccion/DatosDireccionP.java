package med.voll.api.direccion;

import jakarta.validation.constraints.NotBlank;

public record DatosDireccionP(

        @NotBlank
        String urbanizacion,
        @NotBlank
        String distrito,
        @NotBlank
        String codigo_postal,
        @NotBlank
        String complemento,
        @NotBlank
        String numero,
        @NotBlank
        String provincia,
        @NotBlank
        String ciudad) {
}
