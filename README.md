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