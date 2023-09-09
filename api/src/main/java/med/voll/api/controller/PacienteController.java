package med.voll.api.controller;

import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import med.voll.api.pacientes.*;
import med.voll.api.pacientes.DatosActualizarPaciente;
import med.voll.api.pacientes.DatosListadoPaciente;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.web.bind.annotation.*;


import java.util.List;

@RestController
@RequestMapping("/pacientes")
public class PacienteController {

        @Autowired
        private PacienteRepository pacienteRepository;
        @PostMapping
        @Transactional
        public void registrarPaciente(@RequestBody @Valid DatosRegistroPaciente datos) {
            pacienteRepository.save(new Paciente(datos));

        }

        //muestra los pacientes
        @GetMapping
        public Page<DatosListadoPaciente> listadoPacientes(@PageableDefault(size = 5) Pageable paginacion){
                //return pacienteRepository.findAll().stream().map(DatosListadoPaciente::new).toList();
                return pacienteRepository.findByActivoTrue(paginacion).map(DatosListadoPaciente::new);
        }

        @PutMapping
        @Transactional
        public void actualizarMedico(@RequestBody @Valid DatosActualizarPaciente datosActualizarPaciente){
                Paciente paciente = pacienteRepository.getReferenceById(datosActualizarPaciente.id());
                paciente.actualizarDatos(datosActualizarPaciente);

        }

        //DELETE LOGICO
        @DeleteMapping("/{id}")
        @Transactional
        public void eliminarMedico(@PathVariable Long id){
                Paciente paciente = pacienteRepository.getReferenceById(id);
                paciente.desactivarPaciente();
        }
}





