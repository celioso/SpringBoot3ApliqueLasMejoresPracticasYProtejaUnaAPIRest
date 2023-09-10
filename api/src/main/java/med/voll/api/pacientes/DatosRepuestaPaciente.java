package med.voll.api.pacientes;


import med.voll.api.direccion.DatosDireccionP;

public record DatosRepuestaPaciente(Long id, String nombre, String email, String telefono, String documento,
                                    String seguro, DatosDireccionP direccion ) {

}
