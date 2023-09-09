package med.voll.api.direccion;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Embeddable
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DireccionP {

    private String urbanizacion;
    private String distrito;
    private String codigoPostal;
    private String complemento;
    private String numero;
    private String provincia;
    private String ciudad;

    public DireccionP(DatosDireccionP direccionP) {
        this.urbanizacion = direccionP.urbanizacion();
        this.distrito = direccionP.distrito();
        this.codigoPostal = direccionP.codigo_postal();
        this.complemento = direccionP.complemento();
        this.numero = direccionP.numero();
        this.provincia = direccionP.provincia();
        this.ciudad = direccionP.ciudad();
    }

    public DireccionP actualizarDatos(DatosDireccionP direccionP) {
        this.urbanizacion = direccionP.urbanizacion();
        this.distrito = direccionP.distrito();
        this.codigoPostal = direccionP.codigo_postal();
        this.complemento = direccionP.complemento();
        this.numero = direccionP.numero();
        this.provincia = direccionP.provincia();
        this.ciudad = direccionP.ciudad();
        return this;
    }
}
