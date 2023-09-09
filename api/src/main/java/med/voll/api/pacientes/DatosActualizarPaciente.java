package med.voll.api.pacientes;

import jakarta.validation.constraints.NotNull;
import med.voll.api.direccion.DatosDireccionP;

public record DatosActualizarPaciente(@NotNull Long id, String nombre, String documento, DatosDireccionP direccion) {
}
