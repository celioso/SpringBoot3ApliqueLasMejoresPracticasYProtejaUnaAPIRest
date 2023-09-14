# Spring Boot 3: aplique las mejores prácticas y proteja una API Rest

### Proyecto inicial

En este curso, usaremos el mismo proyecto que se completó en el primer curso de Spring Boot. Puede obtener una copia del proyecto desde este repositorio de GitHub:

- [Proyecto inicial](https://github.com/alura-cursos/2770-spring-boot/tree/projeto_inicial "Proyecto inicial")
Ademas tienes aqui los [slides(presentaciones)](https://drive.google.com/drive/folders/1eNnXuuPuxIi70toLvNzjDG2Joet70Kt7?usp=sharing "slides(presentaciones)") que utilizo durante este curso.

## Para saber más: códigos de protocolo HTTP

El protocolo HTTP (Hypertext Transfer Protocol, RFC 2616) es el protocolo encargado de realizar la comunicación entre el cliente, que suele ser un navegador, y el servidor. De esta forma, para cada “solicitud” realizada por el cliente, el servidor responde sí tuvo éxito o no. Si no tiene éxito, la mayoría de las veces, la respuesta del servidor será una secuencia numérica acompañada de un mensaje. Si no sabemos qué significa el código de respuesta, difícilmente sabremos cuál es el problema, por eso es muy importante saber qué son los códigos HTTP y qué significan.

### Categoría de código
Los códigos HTTP (o HTTPS) tienen tres dígitos, y el primer dígito representa la clasificación dentro de las cinco categorías posibles.

- 1XX: Informativo: la solicitud fue aceptada o el proceso aún está en curso;
- 2XX: Confirmación: la acción se completó o se comprendió;
- 3XX: Redirección: indica que se debe hacer o se debió hacer algo más para completar la solicitud;
- 4XX: Error del cliente: indica que la solicitud no se puede completar o contiene una sintaxis incorrecta;
- 5XX: Error del servidor: el servidor falló al concluir la solicitud.

### Principales códigos de error.

Como se mencionó anteriormente, conocer los principales códigos de error HTTP lo ayudará a identificar problemas en sus aplicaciones, además de permitirle comprender mejor la comunicación de su navegador con el servidor de la aplicación a la que intenta acceder.

### Error 403
El código 403 es el error "Prohibido". Significa que el servidor entendió la solicitud del cliente, pero se niega a procesarla, ya que el cliente no está autorizado para hacerlo.

###Error 404
Cuando ingresa una URL y recibe un mensaje de Error 404, significa que la URL no lo llevó a ninguna parte. Puede ser que la aplicación ya no exista, que la URL haya cambiado o que haya ingresado una URL incorrecta.

### Error 500
Es un error menos común, pero aparece de vez en cuando. Este error significa que hay un problema con una de las bases que hace que se ejecute una aplicación. Básicamente, este error puede estar en el servidor que mantiene la aplicación en línea o en la comunicación con el sistema de archivos, que proporciona la infraestructura para la aplicación.

### Error 503
El error 503 significa que el servicio al que se accede no está disponible temporalmente. Las causas comunes son un servidor que está fuera de servicio por mantenimiento o sobrecargado. Los ataques maliciosos como DDoS causan mucho este problema.

### Un consejo final:
Difícilmente podemos guardar en nuestra cabeza lo que significa cada código, por lo que hay sitios web en Internet que tienen todos los códigos y significados para que podamos consultar cuando sea necesario. Hay dos sitios muy conocidos que usan los desarrolladores, uno para cada preferencia: si te gustan los gatos, puedes usar [HTTP Cats](https://http.cat/ "HTTP Cats"); ya, si prefieres perros, usa [HTTP Dogs](https://http.dog/ "HTTP Dogs").

### Haga lo que hicimos: ResponseEntity
¡Ahora está contigo! Realice el mismo procedimiento que hice en clase, implementando `ResponseEntity`, sin embargo, para las funcionalidades del CRUD de los pacientes.

Deberá cambiar todos los métodos de la clase `PacienteController` para que devuelvan el objeto `ResponseEntity`, de la misma manera que se demostró en clase para la clase `MedicoController`:

```java
@PostMapping
@Transactional
public ResponseEntity registrar(@RequestBody @Valid DatosRegistroPaciente datos, UriComponentsBuilder uriBuilder) {
    var paciente = new Paciente(datos);
    repository.save(paciente);

    var uri = uriBuilder.path("/pacientes/{id}").buildAndExpand(paciente.getId()).toUri();
    return ResponseEntity.created(uri).body(new DatosDetalladoPaciente(paciente));
}

@GetMapping
public ResponseEntity<Page<DatosListadoPaciente>> listar(@PageableDefault(size = 10, sort = {"nombre"}) Pageable paginacion) {
    var page = repository.findAllByAtivoTrue(paginacion).map(DatosListadoPaciente::new);
    return ResponseEntity.ok(page);
}

@PutMapping
@Transactional
public ResponseEntity actualizar(@RequestBody @Valid DatosActualizacionPaciente datos) {
    var paciente = repository.getReferenceById(datos.id());
    paciente.actualizarInformacion(datos);

    return ResponseEntity.ok(new DatosDetalladoPaciente(paciente));
}

@DeleteMapping("/{id}")
@Transactional
public ResponseEntity eliminar(@PathVariable Long id) {
    var paciente = repository.getReferenceById(id);
    paciente.eliminar();

    return ResponseEntity.noContent().build();
}
```
Además, debe crear un método más en este Controller, que se encargará de devolver los datos de un paciente:
```java
@GetMapping("/{id}")
public ResponseEntity detallar(@PathVariable Long id) {
    var paciente = repository.getReferenceById(id);
    return ResponseEntity.ok(new DatosDetalladoPaciente(paciente));
}
```
También necesita crear el DTO `DatosDetalladoPaciente`:

```java
public record DatosDetalladoPaciente(String nombre, String email, String telefono, String documentoIdentidad, Direccion direccion) { 
    public DatosDetalladoPaciente(Paciente paciente) { 
        this(paciente.getNombre(), paciente.getEmail(), paciente.getTelefono(), paciente.getDocumentoIdentidad(), paciente.getDireccion()); 
    }
} 
```

### Lo que aprendimos

En esta clase, aprendiste a:

- Usar la clase ResponseEntity, de Spring, para personalizar los retornos de los métodos de una clase Controller;
- Modificar el código HTTP devuelto en las respuestas de la API;
- Agregar encabezados a las respuestas de la API;
- Utilice los códigos HTTP más apropiados para cada operación realizada en la API.

### Proyecto del aula anterior

¿Comenzando en esta etapa? Aquí puedes descargar los archivos del proyecto que hemos avanzado hasta el aula anterior.

[Descargue los archivos en Github](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/tree/clase-1 "Descargue los archivos en Github") o haga clic[ aquí](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/archive/refs/heads/clase-1.zip " aquí") para descargarlos directamente.

### Para saber más: propiedades de Spring Boot

A lo largo de los cursos, tuvimos que agregar algunas propiedades al archivo application.properties para hacer configuraciones en el proyecto, como, por ejemplo, configuraciones de acceso a la base de datos.

Spring Boot tiene cientos de propiedades que podemos incluir en este archivo, por lo que es imposible memorizarlas todas. Por ello, es importante conocer la documentación que enumera todas estas propiedades, ya que eventualmente necesitaremos consultarla.

Puede acceder a la documentación oficial en el enlace: Common Application Properties.

### Para saber más: propiedades de Spring Boot

A lo largo de los cursos, tuvimos que agregar algunas propiedades al archivo `application.properties` para hacer configuraciones en el proyecto, como, por ejemplo, configuraciones de acceso a la base de datos.

Spring Boot tiene cientos de propiedades que podemos incluir en este archivo, por lo que es imposible memorizarlas todas. Por ello, es importante conocer la documentación que enumera todas estas propiedades, ya que eventualmente necesitaremos consultarla.

Puede acceder a la documentación oficial en el enlace: [Common Application Properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html "Common Application Properties").

### Para saber más: mensajes en español

Por defecto, Bean Validation devuelve mensajes de error en inglés, sin embargo, hay una traducción de estos mensajes al español ya implementada en esta especificación.

En el protocolo HTTP hay un encabezado llamado Accept-Language, que sirve para indicar al servidor el idioma preferido del cliente que activa la solicitud. Podemos utilizar esta cabecera para indicarle a Spring el idioma deseado, para que en la integración con Bean Validation pueda buscar mensajes según el idioma indicado.

En Insomnia, y también en otras herramientas similares, existe una opción llamada Header en la que podemos incluir cabeceras a enviar en la petición. Si agregamos el encabezado Accept-Language con el valor es, los mensajes de error de Bean Validation se devolverán automáticamente en español.

Nota: Bean Validation solo traduce los mensajes de error a unos pocos idiomas.

### Para saber más: personalización de mensajes de error

Es posible que haya notado que Bean Validation tiene un mensaje de error para cada una de sus anotaciones. Por ejemplo, cuando la validación falla en algún atributo anotado con `@NotBlank`, el mensaje de error será: must not be blank.

Estos mensajes de error no se definieron en la aplicación, ya que son mensajes de error estándar de Bean Validation. Sin embargo, si lo desea, puede personalizar dichos mensajes.

Una de las formas de personalizar los mensajes de error es agregar el atributo del mensaje a las anotaciones de validación:

```java
public record DatosCadastroMedico(
    @NotBlank(message = "Nombre es obligatorio")
    String nombre,

    @NotBlank(message = "Email es obligatorio")
    @Email(message = "Formato de email es inválido")
    String email,

    @NotBlank(message = "Teléfono es obligatorio")
    String telefono,

    @NotBlank(message = "CRM es obligatorio")
    @Pattern(regexp = "\\d{4,6}", message = "Formato do CRM es inválido")
    String crm,

    @NotNull(message = "Especialidad es obligatorio")
    Especialidad especialidad,

    @NotNull(message = "Datos de dirección son obligatorios")
    @Valid DatosDireccion direccion) {}
```

Otra forma es aislar los mensajes en un archivo de propiedades, que debe tener el nombre ValidationMessages.properties y estar creado en el directorio src/main/resources:

```java
nombre.obligatorio=El nombre es obligatorio
email.obligatorio=Correo electrónico requerido
email.invalido=El formato del correo electrónico no es válido
phone.obligatorio=Teléfono requerido
crm.obligatorio=CRM es obligatorio
crm.invalido=El formato CRM no es válido
especialidad.obligatorio=La especialidad es obligatoria
address.obligatorio=Los datos de dirección son obligatorios
```

Y, en las anotaciones, indicar la clave de las propiedades por el propio atributo `message`, delimitando con los caracteres { e }:

```java
public record DatosRegistroMedico(
    @NotBlank(message = "{nombre.obligatorio}")
    String nombre,

    @NotBlank(message = "{email.obligatorio}")
    @Email(message = "{email.invalido}")
    String email,

    @NotBlank(message = "{telefono.obligatorio}")
    String telefono,

    @NotBlank(message = "{crm.obligatorio}")
    @Pattern(regexp = "\\d{4,6}", message = "{crm.invalido}")
    String crm,

    @NotNull(message = "{especialidad.obligatorio}")
    Especialidad especialidad,

    @NotNull(message = "{direccion.obligatorio}")
    @Valid DatosDireccion direccion) {}
```

### Haga lo que hicimos: RestControllerAdvice

¡Ahora está contigo! Realice el mismo procedimiento que hice en clase, creando una clase responsable de manejar las excepciones que pueden ocurrir en las clases Controller.

Deberá crear una clase similar a esta:

```java
@RestControllerAdvice
public class ManejadorDeErrores {

@ExceptionHandler(EntityNotFoundException.class)
public ResponseEntity manejarError404() {
    return ResponseEntity.notFound().build();
}

@ExceptionHandler(MethodArgumentNotValidException.class)
public ResponseEntity manejarErro400(MethodArgumentNotValidException ex) {
    var errores = ex.getFieldErrors();
    return ResponseEntity.badRequest().body(errores.stream().map(DatosErrorValidacion::new).toList());
}

private record DatosErrorValidacion(String campo, String mensaje) {
    public DatosErrorValidacion(FieldError error) {
        this(error.getField(), error.getDefaultMessage());
    }
}
}
```

Además, también debe agregar la siguiente propiedad al archivo application.properties para evitar que el stacktracer de la excepción sea devuelto en el cuerpo de la respuesta:

```java
server.error.include-stacktrace=never
```

### Lo que aprendimos

En esta clase, aprendiste a:

- Crear una clase para aislar el manejo de excepciones de API, utilizando la anotación `@RestControllerAdvice`;
- Utilizar la anotación `@ExceptionHandler`, de Spring, para indicar qué excepción debe capturar un determinado método de la clase de manejo de errores;
- Manejar errores 404 (Not Found) en la clase de manejo de errores;
- Manejar errores 400 (Bad Request), para errores de validación de Bean Validation, en la clase de manejo de errores;
- Simplificar el JSON devuelto por la API en casos de error de validación de Bean Validation.

### Proyecto del aula anterior

¿Comenzando en esta etapa? Aquí puedes descargar los archivos del proyecto que hemos avanzado hasta el aula anterior.

[Descargue los archivos en Github](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/tree/clase-2 "Descargue los archivos en Github") o haga clic [aquí](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/archive/refs/heads/clase-2.zip "aquí") para descargarlos directamente.

### Para saber más: hash de contraseña

Al implementar una funcionalidad de autenticación en una aplicación, independientemente del lenguaje de programación utilizado, deberá tratar con los datos de inicio de sesión y contraseña de los usuarios, y deberán almacenarse en algún lugar, como, por ejemplo, una base de datos.

Las contraseñas son información confidencial y no deben almacenarse en texto sin formato, ya que si una persona malintencionada logra acceder a la base de datos, podrá acceder a las contraseñas de todos los usuarios. Para evitar este problema, siempre debe usar algún algoritmo hash en las contraseñas antes de almacenarlas en la base de datos.

Hashing no es más que una función matemática que convierte un texto en otro texto totalmente diferente y difícil de deducir. Por ejemplo, el texto “Mi nombre es Rodrigo” se puede convertir en el texto 8132f7cb860e9ce4c1d9062d2a5d1848, utilizando el algoritmo hash MD5.

Un detalle importante es que los algoritmos de hash deben ser unidireccionales, es decir, no debe ser posible obtener el texto original a partir de un hash. Así, para saber si un usuario ingresó la contraseña correcta al intentar autenticarse en una aplicación, debemos tomar la contraseña que ingresó y generar su hash, para luego compararla con el hash que está almacenado en la base de datos.

Hay varios algoritmos hashing que se pueden usar para transformar las contraseñas de los usuarios, algunos de los cuales son más antiguos y ya no se consideran seguros en la actualidad, como MD5 y SHA1. Los principales algoritmos actualmente recomendados son:

 - Bcrypt
 - Scrypt
 - Argon2
 - PBKDF2

A lo largo del curso utilizaremos el algoritmo BCrypt, que es bastante popular hoy en día. Esta opción también tiene en cuenta que Spring Security ya nos proporciona una clase que lo implementa.

### Para saber más: documentación de Spring Data

Como aprendimos en videos anteriores, Spring Data usa su propio patrón de nomenclatura de métodos que debemos seguir para que pueda generar consultas SQL correctamente.

Hay algunas palabras reservadas que debemos usar en los nombres de los métodos, como *findBy* y *existBy*, para indicarle a Spring Data cómo debe ensamblar la consulta que queremos. Esta característica es bastante flexible y puede ser un poco compleja debido a las diversas posibilidades existentes.

Para conocer más detalles y comprender mejor cómo ensamblar consultas dinámicas con Spring Data, acceda a su [documentación oficial](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/ "documentación oficial").

### Haga lo que hicimos: autenticación API

¡Ahora está contigo! Realice el mismo procedimiento que hice en clase, implementando el proceso de autenticación en la API.

Primero, deberá agregar Spring Security al proyecto, incluidas estas dependencias en el pom.xml:

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

Después de eso, deberá crear las clases *Usuario*, *UsuarioRepository* y *AutenticacionService* en el proyecto, como se muestra a continuación:

```java
@Table(name = "usuarios")
@Entity(name = "Usuario")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Usuario implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String login;
    private String contrasena;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return contrasena;
    }

    @Override
    public String getUsername() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```
```java
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    UserDetails findByLogin(String login);
}
```

```java
@Service
public class AutenticacionService implements UserDetailsService {

    @Autowired
    private UsuarioRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByLogin(username);
    }
}
```

También debe crear una nueva migración en el proyecto para crear la tabla de usuario (IMPORTANTE: ¡recuerde detener el proyecto antes de crear la nueva migración!):

```java
create table usuarios(
    id bigint not null auto_increment,
    login varchar(100) not null,
    contrasena varchar(255) not null,

    primary key(id)
);
```

Además, también deberá crear la clase con la configuración de seguridad de la API:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

Finalmente, deberá crear una clase Controller y un DTO para manejar las solicitudes de autenticación en la API:

```java
@RestController
@RequestMapping("/login")
public class AutenticacionController {

    @Autowired
    private AuthenticationManager manager;

    @PostMapping
    public ResponseEntity realizarLogin(@RequestBody @Valid DatosAutenticacion datos) {
        var token = new UsernamePasswordAuthenticationToken(datos.login(), datos.contrasena());
        var authenticaon = manager.authenticate(token);

        return ResponseEntity.ok().build();
    }
}
```
```java
public record DatosAutenticacion(String login, String contrasena) {
}
```

Para probar la autenticación, deberá insertar un registro de usuario en su base de datos, en la tabla de usuarios:
```java
insert into usuarios values(1, 'ana.souza@voll.med', '$2a$10$Y50UaMFOxteibQEYLrwuHeehHYfcoafCopUazP12.rqB41bsolF5.');
```

### Lo que aprendimos

En esta clase, aprendiste a:

- Identificar cómo funciona el proceso de autenticación y autorización en una API Rest;
- Agregar Spring Security al proyecto;
- Cómo funciona el comportamiento padrón de Spring Security en una aplicación;
- Implementar el proceso de autenticación en la API, de forma Stateless, utilizando clases y configuraciones de Spring Security.

### Proyecto del aula anterior

¿Comenzando en esta etapa? Aquí puedes descargar los archivos del proyecto que hemos avanzado hasta el aula anterior.

[Descargue los archivos en Github](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/tree/clase-3 "Descargue los archivos en Github") o haga clic [aquí](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/archive/refs/heads/clase-3.zip "aquí") para descargarlos directamente.

### Para saber más: otra información sobre el Token

Además del Issuer, Subject y fecha de expiración, podemos incluir otra información en el token JWT, según las necesidades de la aplicación. Por ejemplo, podemos incluir el id del usuario en el token, simplemente usando el método `withClaim`:

```java
return JWT.create()
    .withIssuer("API Voll.med")
    .withSubject(usuario.getLogin())

    .withClaim("id", usuario.getId())

    .withExpiresAt(fechaExpiracion())
    .sign(algoritmo);
```

El método `withClaim` recibe dos parámetros, el primero es un String que identifica el nombre del claim (propiedad almacenada en el token), y el segundo la información a almacenar.

###  Haga lo que hicimos: generación de tokens

¡Ahora está contigo! Realice el mismo procedimiento que hice en clase, implementando la generación de tokens JWT cuando un usuario se autentica en la API.

Primero, deberá agregar la biblioteca Auth0 java-jwt a su proyecto, incluida esta dependencia en su pom.xml:

```java
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.2.1</version>
</dependency>
```

A continuación, será necesario crear la clase encargada de generar los tokens:

```java
@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    public String generarToken(Usuario usuario) {
        try {
            var algoritmo = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("API Voll.med")
                    .withSubject(usuario.getLogin())
                    .withExpiresAt(fechaExpiracion())
                    .sign(algoritmo);
        } catch (JWTCreationException exception){
            throw new RuntimeException("error al generar el  token jwt", exception);
        }
    }

    private Instant fechaExpiracion() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

}
```

También deberá agregar la siguiente propiedad al archivo `application.properties`:

```java
api.security.token.secret=${JWT_SECRET:12345678}
```

Finalmente, será necesario crear el DTO DatosTokenJWT y cambiar la clase AutenticacionController:

```java
public record DatosTokenJWT(String token) {}
@RestController
@RequestMapping("/login")
public class AutenticacionController {

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;

    @PostMapping
    public ResponseEntity  realizarLogin(@RequestBody @Valid DatosAutenticacion datos) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(datos.login(), datos.contrasena());
        var authentication = manager.authenticate(authenticationToken);

        var tokenJWT = tokenService.generarToken((Usuario) authentication.getPrincipal());

        return ResponseEntity.ok(new DatosTokenJWT(tokenJWT));
    }

}
```

### Lo que aprendimos

¿Qué hemos aprendido?

- En esta clase, aprendiste a:
- Agregar la biblioteca `Auth0 java-jwt` como una dependencia del proyecto;
- Utilizar esta biblioteca para generar un token en la API;
- Inyectar una propiedad del archivo `application.properties` en una clase administrada por Spring, usando la anotación `@Value`;
- Devolver un token generado en la API cuando un usuario se autentica.

### Proyecto del aula anterior

¿Comenzando en esta etapa? Aquí puedes descargar los archivos del proyecto que hemos avanzado hasta el aula anterior.

[Descargue los archivos en Github ](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/tree/clase-4 "Descargue los archivos en Github ")o haga clic [aquí](https://github.com/alura-es-cursos/spring-boot-buenas-practicas-security/archive/refs/heads/clase-4.zip "aquí") para descargarlos directamente.
