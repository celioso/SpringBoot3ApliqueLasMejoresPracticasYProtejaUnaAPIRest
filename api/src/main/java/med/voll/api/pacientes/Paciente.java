package med.voll.api.pacientes;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import med.voll.api.direccion.DireccionP;
import med.voll.api.medico.DatosActualizarMedico;

@Getter
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = "Pacientes")
@Table(name = "pacientes")
public class Paciente {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String nombre;
    private String email;
    private String telefono;
    private String documento;
    private String seguro;  //SANITAS,NUEVAEPS,COLSANITAS,COOMEVA
    private Boolean activo;


    @Embedded
    private DireccionP direccionP;

    public Paciente(DatosRegistroPaciente datos) {
        this.activo = true;
        this.nombre = datos.nombre();
        this.email = datos.email();
        this.telefono = datos.telefono();
        this.documento = datos.documento();
        this.seguro = String.valueOf(datos.seguro());
        this.direccionP = new DireccionP(datos.direccionP());
    }

    public void actualizarDatos(DatosActualizarPaciente datosActualizarPaciente) {
        if (datosActualizarPaciente.nombre() != null){
            this.nombre = datosActualizarPaciente.nombre();
        }

        if (datosActualizarPaciente.documento() != null){
            this.documento = datosActualizarPaciente.documento();
        }
        if (datosActualizarPaciente.direccion() != null){
            this.direccionP = direccionP.actualizarDatos(datosActualizarPaciente.direccion());
        }
    }

    public void desactivarPaciente() {
        this.activo = false;
    }
}
