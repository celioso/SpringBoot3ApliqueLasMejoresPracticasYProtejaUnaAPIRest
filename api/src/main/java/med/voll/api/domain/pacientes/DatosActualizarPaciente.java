package med.voll.api.domain.pacientes;

import jakarta.validation.constraints.NotNull;
import med.voll.api.domain.direccion.DatosDireccionP;

public record DatosActualizarPaciente(@NotNull Long id, String nombre, String documento, DatosDireccionP direccion) {
}
