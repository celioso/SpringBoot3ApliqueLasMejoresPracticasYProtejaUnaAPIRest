package med.voll.api.domain.pacientes;


import med.voll.api.domain.direccion.DatosDireccionP;

public record DatosRepuestaPaciente(Long id, String nombre, String email, String telefono, String documento,
                                    String seguro, DatosDireccionP direccion ) {

}
