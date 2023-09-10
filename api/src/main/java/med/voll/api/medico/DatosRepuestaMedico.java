package med.voll.api.medico;

import med.voll.api.direccion.DatosDireccion;

public record DatosRepuestaMedico(Long id, String nombre, String email, String telefono, String documento,
                                  DatosDireccion direccion ) {

}
