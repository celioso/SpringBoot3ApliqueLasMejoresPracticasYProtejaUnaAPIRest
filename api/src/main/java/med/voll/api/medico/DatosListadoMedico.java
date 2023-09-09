package med.voll.api.medico;

public record DatosListadoMedico(Long id, String nombre, String especialidad, String telefono, String email) {
    public DatosListadoMedico(Medico medico){
    this(medico.getId(),
            medico.getNombre(),
            medico.getEspecialidad().toString(),
            medico.getTelefono(),
            medico.getEmail());
    }
}
