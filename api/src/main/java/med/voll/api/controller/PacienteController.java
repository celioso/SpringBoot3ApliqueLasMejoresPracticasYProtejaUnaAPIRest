package med.voll.api.controller;

import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import med.voll.api.direccion.DatosDireccionP;
import med.voll.api.pacientes.*;
import med.voll.api.pacientes.DatosActualizarPaciente;
import med.voll.api.pacientes.DatosListadoPaciente;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;


@RestController
@RequestMapping("/pacientes")
public class PacienteController {

        @Autowired
        private PacienteRepository pacienteRepository;
        @PostMapping
        @Transactional
        public ResponseEntity<DatosRepuestaPaciente> registrarPaciente(@RequestBody @Valid DatosRegistroPaciente datosRegistroPaciente,
                                                                       UriComponentsBuilder uriComponentsBuilder) {
            Paciente paciente = pacienteRepository.save(new Paciente(datosRegistroPaciente));
            DatosRepuestaPaciente datosRepuestaPaciente = new DatosRepuestaPaciente(paciente.getId(), paciente.getNombre(), paciente.getEmail(), paciente.getTelefono(), paciente.getDocumento(),
                    paciente.getSeguro(),
                    new DatosDireccionP(paciente.getDireccionP().getUrbanizacion(),paciente.getDireccionP().getDistrito(), paciente.getDireccionP().getCodigoPostal(),
                            paciente.getDireccionP().getComplemento(), paciente.getDireccionP().getNumero(),paciente.getDireccionP().getProvincia(),
                            paciente.getDireccionP().getCiudad()));

            URI url = uriComponentsBuilder.path("/pacientes/{id}").buildAndExpand(paciente.getId()).toUri();
            return ResponseEntity.created(url).body(datosRepuestaPaciente);

        }

        //muestra los pacientes
        @GetMapping
        public ResponseEntity<Page<DatosListadoPaciente>> listadoPacientes(@PageableDefault(size = 5) Pageable paginacion){
                //return pacienteRepository.findAll().stream().map(DatosListadoPaciente::new).toList();
                return ResponseEntity.ok(pacienteRepository.findByActivoTrue(paginacion).map(DatosListadoPaciente::new));
        }

        @PutMapping
        @Transactional
        public ResponseEntity<DatosRepuestaPaciente> actualizarMedico(@RequestBody @Valid DatosActualizarPaciente datosActualizarPaciente){
                Paciente paciente = pacienteRepository.getReferenceById(datosActualizarPaciente.id());
                paciente.actualizarDatos(datosActualizarPaciente);
                return ResponseEntity.ok(new DatosRepuestaPaciente(paciente.getId(), paciente.getNombre(), paciente.getEmail(), paciente.getTelefono(), paciente.getDocumento(),
                        paciente.getSeguro(),
                        new DatosDireccionP(paciente.getDireccionP().getUrbanizacion(),paciente.getDireccionP().getDistrito(), paciente.getDireccionP().getCodigoPostal(),
                                paciente.getDireccionP().getComplemento(), paciente.getDireccionP().getNumero(),paciente.getDireccionP().getProvincia(),
                                paciente.getDireccionP().getCiudad())));

        }

        //DELETE LOGICO
        @DeleteMapping("/{id}")
        @Transactional
        public ResponseEntity<DatosRepuestaPaciente> eliminarMedico(@PathVariable Long id){
                Paciente paciente = pacienteRepository.getReferenceById(id);
                paciente.desactivarPaciente();
                return ResponseEntity.noContent().build();
        }

        @GetMapping("/{id}")

        public ResponseEntity<DatosRepuestaPaciente> retornaDatosMedicos(@PathVariable Long id){
                Paciente paciente = pacienteRepository.getReferenceById(id);
                var datosPaciente = new DatosRepuestaPaciente(paciente.getId(), paciente.getNombre(), paciente.getEmail(), paciente.getTelefono(), paciente.getDocumento(),
                        paciente.getSeguro(),
                        new DatosDireccionP(paciente.getDireccionP().getUrbanizacion(),paciente.getDireccionP().getDistrito(), paciente.getDireccionP().getCodigoPostal(),
                                paciente.getDireccionP().getComplemento(), paciente.getDireccionP().getNumero(),paciente.getDireccionP().getProvincia(),
                                paciente.getDireccionP().getCiudad()));
                return ResponseEntity.ok(datosPaciente );
        }
}





