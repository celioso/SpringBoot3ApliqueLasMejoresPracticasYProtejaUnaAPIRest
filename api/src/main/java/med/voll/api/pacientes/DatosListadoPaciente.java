package med.voll.api.pacientes;



public record DatosListadoPaciente(Long id, String nombre, String seguro, String telefono, String email) {
    public DatosListadoPaciente(Paciente paciente){
        this(paciente.getId(),
                paciente.getNombre(),
                paciente.getSeguro(),
                paciente.getTelefono(),
                paciente.getEmail());
    }
}
