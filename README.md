# OIKOS

Versión de desarrollo del simulador.

## Arranque local

```bash
npm install
npm start
```

Abrir `http://localhost:3000/`.

## Historial

Las sesiones terminadas se guardan dentro de `estado_actual.json` en `historialSesiones`. Además se conserva una copia de seguridad en `historiales/`.

Una sesión pasa al historial cuando el administrador cierra la producción y comienza una nueva sesión.

Las consolas solicitan explícitamente el historial al servidor mediante `solicitarHistorial`, por lo que no dependen de una actualización previa del navegador.

## Calculadora

La calculadora del jugador muestra producción y desperdicio de trigo y hierro. Para los procesos 1 y 2, el desperdicio corresponde al insumo que queda fuera de la proporción necesaria del proceso. El proceso 3 no tiene desperdicio.

## Historial y auditoría

El historial de OIKOS conserva una traza común para administrador y jugadores, y el superadministrador puede consultar la misma información por experimento. Cada sesión cerrada registra:

- hora de apertura de la sesión y de las entregas;
- hora de cierre de entregas y apertura de producción;
- hora de cierre de producción y fin de la sesión;
- recursos de cada jugador al comenzar la sesión;
- recursos de cada jugador después de las entregas;
- cada entrega individual, con usuario, nombre visible, cantidades y hora;
- proceso elegido y producción obtenida por jugador;
- recursos finales de cada jugador;
- ediciones y eliminaciones realizadas por el administrador.

La descarga Excel genera hojas separadas de **Tiempos**, **Recursos iniciales**, **Entregas**, **Producción** y **Ediciones**.
