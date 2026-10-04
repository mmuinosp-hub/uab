# OIKOS — Superadministrador de experimentos

Esta versión amplía la consola para consultar experimentos sin modificar datos.

Incluye:
- listado de experimentos/salas;
- identificación de experimentos terminados;
- participantes;
- sesiones realizadas;
- número de entregas;
- consulta detallada de entregas;
- consulta detallada de producciones y proceso elegido;
- consulta de registros de sesiones.

La consola es de solo lectura.

Importante:
La detección de sesiones históricas utiliza los campos `historialSesiones`/`sesiones` si existen en la estructura actual y, como respaldo, `numeroSesion - 1`. Si el servidor guarda el historial con otro nombre, habrá que conectar ese nombre concreto para obtener el desglose completo de sesiones.

Para activarla:
PowerShell:
$env:SUPERADMIN_PASSWORD="una-clave-segura"
node server.js

Abrir:
http://localhost:3000/superadmin.html
