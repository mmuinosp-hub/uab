/*
 * OIKOS — servidor rediseñado
 * Compatible con los eventos Socket.IO de la versión 0.2, pero con:
 * - autenticación por socket y autorización por rol
 * - contraseñas almacenadas con scrypt (crypto nativo de Node)
 * - estado interno separado del estado público
 * - máquina de estados de fase
 * - límite configurable de entregas
 * - sesiones numeradas
 * - timestamps ISO
 * - persistencia serializada y atómica
 * - IDs robustos
 * - reconexión del administrador
 * - validación estricta de entradas
 *
 * © 2025 Manuel Muiños
 * Licencia: CC BY-NC-ND 4.0
 */

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const salas = Object.create(null);
const estadoFile = path.join(__dirname, "estado_actual.json");

// -----------------------------------------------------------------------------
// CONFIGURACIÓN
// -----------------------------------------------------------------------------

const DEFAULT_CONFIG = Object.freeze({
  maxEntregas: 5,
  tipoJuego: "capital",
  informacionPublica: {
    cantidadesJugadores: true,
    entregasGlobales: true,
    procesosElegidos: false,
    historiales: true,
  },
});

// Contraseña de la consola de superadministración.
// En producción se recomienda definirla mediante la variable de entorno
// SUPERADMIN_PASSWORD. Si no se define, la consola superadmin queda desactivada.
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || "";

// -----------------------------------------------------------------------------
// UTILIDADES
// -----------------------------------------------------------------------------

function generarId() {
  return crypto.randomUUID();
}

function saneaSala(valor = "") {
  return String(valor)
    .trim()
    .replace(/[^\p{L}\p{N}_-]/gu, "")
    .slice(0, 40);
}

function validaNombreJugador(valor = "") {
  const nombre = String(valor).trim();
  if (!nombre || nombre.length > 40) return null;
  if (nombre === "__viewer__") return null;
  if (!/^[\p{L}\p{N}_ .-]+$/u.test(nombre)) return null;
  return nombre;
}

function validaNombreVisible(valor, fallback = "") {
  const nombre = String(valor ?? fallback).trim();
  if (!nombre) return String(fallback).trim();
  if (nombre.length > 100) return null;
  // Permitimos nombres visibles más amplios que el usuario.
  if (/^[\p{C}]+$/u.test(nombre)) return null;
  return nombre;
}

function validaPassword(valor) {
  return typeof valor === "string" && valor.length >= 1 && valor.length <= 200;
}

function numeroNoNegativo(valor, fallback = 0) {
  if (typeof valor === "number") {
    return Number.isFinite(valor) && valor >= 0 ? valor : fallback;
  }

  if (typeof valor !== "string" || valor.trim() === "") return fallback;

  // Aceptamos punto decimal. No aceptamos basura al final.
  const texto = valor.trim();
  if (!/^(?:\d+|\d+\.\d+|\.\d+)$/.test(texto)) return fallback;

  const n = Number(texto);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function enteroPositivo(valor, fallback) {
  const n = Number(valor);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function ahora() {
  return new Date().toISOString();
}

function respuestaError(socket, mensaje, codigo = "ERROR") {
  socket.emit("error", mensaje);
  socket.emit("errorJuego", { codigo, mensaje });
}

function copiar(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function sesionObjetivoAuditoria(data) {
  const haySesionesCerradas = Array.isArray(data?.historialSesiones) && data.historialSesiones.length > 0;
  return data?.fase === "pausa" && haySesionesCerradas
    ? Number(data.numeroSesion || 1) + 1
    : Number(data?.numeroSesion || 1);
}

function registrarAuditoria(data, tipo, detalle = {}) {
  if (!data) return;
  data.historialAuditoria = Array.isArray(data.historialAuditoria)
    ? data.historialAuditoria
    : [];
  const sesion = sesionObjetivoAuditoria(data);
  data.historialAuditoria.push({
    id: generarId(),
    timestamp: ahora(),
    sesion,
    tipo,
    ...copiar(detalle),
  });
}

// -----------------------------------------------------------------------------
// CONTRASEÑAS: scrypt nativo, sin dependencia externa
// -----------------------------------------------------------------------------

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt.toString("hex")}$${derivedKey.toString("hex")}`);
    });
  });
}

function verificarPassword(password, stored) {
  return new Promise((resolve) => {
    if (typeof password !== "string" || typeof stored !== "string") {
      return resolve(false);
    }

    const partes = stored.split("$");
    if (partes.length !== 3 || partes[0] !== "scrypt") return resolve(false);

    try {
      const salt = Buffer.from(partes[1], "hex");
      const esperado = Buffer.from(partes[2], "hex");

      crypto.scrypt(password, salt, esperado.length, (err, derivado) => {
        if (err || derivado.length !== esperado.length) return resolve(false);
        resolve(crypto.timingSafeEqual(derivado, esperado));
      });
    } catch {
      resolve(false);
    }
  });
}

// Compatibilidad de migración: permite reconocer temporalmente contraseñas
// antiguas en texto plano y convertirlas a scrypt al iniciar sesión.
async function verificarYActualizarPassword(password, stored) {
  if (typeof stored !== "string") return false;

  if (stored.startsWith("scrypt$")) {
    return verificarPassword(password, stored);
  }

  // Formato antiguo: texto plano.
  if (stored === password) return true;

  return false;
}

// -----------------------------------------------------------------------------
// PERSISTENCIA
// -----------------------------------------------------------------------------

let colaGuardado = Promise.resolve();

function encolarGuardado() {
  colaGuardado = colaGuardado
    .then(() => {
      // El historial cerrado ya tiene su propio archivo por sala. No lo
      // duplicamos en estado_actual.json: allí solo debe quedar el estado
      // operativo necesario para reanudar la partida.
      const estadoCompacto = Object.create(null);
      for (const [nombreSala, datosSala] of Object.entries(salas)) {
        const { historialSesiones, ...estadoOperativo } = datosSala;
        estadoCompacto[nombreSala] = estadoOperativo;
      }
      return writeAtomic(estadoFile, JSON.stringify(estadoCompacto));
    })
    .catch((err) => {
      console.error("Error al guardar estado:", err);
    });

  return colaGuardado;
}

async function writeAtomic(filePath, content) {
  const dir = path.dirname(filePath);
  await fsp.mkdir(dir, { recursive: true });

  const tmp = path.join(
    dir,
    `.${path.basename(filePath)}.${crypto.randomBytes(8).toString("hex")}.tmp`
  );

  try {
    await fsp.writeFile(tmp, content, { encoding: "utf8", mode: 0o600 });
    await fsp.rename(tmp, filePath);
  } finally {
    try {
      await fsp.unlink(tmp);
    } catch {
      // El temporal puede haber sido renombrado correctamente.
    }
  }
}

async function cargarHistorialPersistente(sala) {
  const file = path.join(__dirname, "historiales", `historial_${sala}.json`);
  try {
    if (!fs.existsSync(file)) return [];
    const raw = await fsp.readFile(file, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error(`No se pudo cargar el historial persistente de ${sala}:`, err);
    return [];
  }
}

async function guardarHistorialPersistente(sala) {
  const data = salas[sala];
  if (!data) return;
  const dir = path.join(__dirname, "historiales");
  await fsp.mkdir(dir, { recursive: true });
  const file = path.join(dir, `historial_${sala}.json`);
  await writeAtomic(file, JSON.stringify(data.historialSesiones || [], null, 2));
}

async function cargarEstado() {
  if (!fs.existsSync(estadoFile)) return;

  try {
    const raw = await fsp.readFile(estadoFile, "utf8");
    const limpio = raw.replace(/^\uFEFF/, "").trim();

    // Un archivo vacío, truncado o corrupto no debe impedir que arranque el servidor.
    // Se conserva una copia para poder recuperar los datos manualmente.
    if (!limpio) {
      const backup = `${estadoFile}.corrupto-${Date.now()}.bak`;
      await fsp.copyFile(estadoFile, backup);
      console.warn(`El archivo de estado estaba vacío. Se ha guardado una copia en ${path.basename(backup)} y se inicia con estado vacío.`);
      return;
    }

    let data;
    try {
      data = JSON.parse(limpio);
    } catch (parseErr) {
      const backup = `${estadoFile}.corrupto-${Date.now()}.bak`;
      await fsp.copyFile(estadoFile, backup);
      console.error(`El archivo de estado contiene JSON inválido. Se ha guardado una copia en ${path.basename(backup)}.`);
      console.error(parseErr.message);
      return;
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("El estado persistido no es un objeto");
    }

    for (const [sala, valor] of Object.entries(data)) {
      salas[sala] = normalizarSala(valor);
      const historialPersistente = await cargarHistorialPersistente(sala);
      const historialEnEstado = salas[sala].historialSesiones;
      if (historialPersistente.length >= historialEnEstado.length) {
        salas[sala].historialSesiones = historialPersistente;
      } else {
        // Migra historiales de versiones anteriores antes de dejar de incluirlos
        // en estado_actual.json. Así no se pierden si falta el archivo separado.
        await guardarHistorialPersistente(sala);
      }
    }

    console.log("Estado recuperado desde disco");
  } catch (err) {
    console.error("Error al cargar estado guardado:", err);
  }
}

async function migrarArchivosHistoricosGenericos() {
  // Compatibilidad con versiones que guardaban simplemente entregas.json y
  // produccion.json (o variantes equivalentes) sin incorporarlos al historial
  // de la sala. Si solo existe una sala, podemos asociarlos sin ambigüedad.
  const nombresSalas = Object.keys(salas);
  if (nombresSalas.length === 0) return;

  const candidatos = [];
  const raices = [__dirname, path.join(__dirname, "historiales")];
  for (const dir of raices) {
    if (!fs.existsSync(dir)) continue;
    let archivos = [];
    try { archivos = await fsp.readdir(dir); } catch { continue; }
    for (const archivo of archivos) {
      if (!archivo.toLowerCase().endsWith('.json')) continue;
      if (archivo === 'estado_actual.json' || archivo.startsWith('historial_')) continue;
      if (/^(entregas|entrega)(?:[_-].*)?\.json$/i.test(archivo) ||
          /^(produccion|producción)(?:[_-].*)?\.json$/i.test(archivo)) {
        candidatos.push(path.join(dir, archivo));
      }
    }
  }
  if (!candidatos.length) return;

  const porSala = nombresSalas.length === 1 ? new Map([[nombresSalas[0], candidatos]]) : new Map();
  if (nombresSalas.length > 1) return; // No adivinamos entre varias salas.

  const sala = nombresSalas[0];
  const data = salas[sala];
  const archivosEntrega = candidatos.filter(f => /^(entregas|entrega)(?:[_-].*)?\.json$/i.test(path.basename(f)));
  const archivosProduccion = candidatos.filter(f => /^(produccion|producción)(?:[_-].*)?\.json$/i.test(path.basename(f)));

  let entregas = [];
  let produccion = {};
  for (const f of archivosEntrega) {
    try {
      const parsed = JSON.parse(await fsp.readFile(f, 'utf8'));
      if (Array.isArray(parsed)) entregas.push(...parsed);
    } catch (err) { console.error(`No se pudo migrar ${f}:`, err); }
  }
  for (const f of archivosProduccion) {
    try {
      const parsed = JSON.parse(await fsp.readFile(f, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        produccion = { ...produccion, ...parsed };
      }
    } catch (err) { console.error(`No se pudo migrar ${f}:`, err); }
  }

  if (!entregas.length && !Object.keys(produccion).length) return;

  const sesionesEntrega = [...new Set(entregas.map(e => Number(e?.sesion)).filter(Number.isInteger))];
  const numero = sesionesEntrega.length ? Math.max(...sesionesEntrega) : Math.max(1, Number(data.numeroSesion || 2) - 1);
  const yaExiste = (data.historialSesiones || []).some(x => Number(x.numeroSesion) === numero && ((x.entregas || []).length || Object.keys(x.produccion || {}).length));
  if (yaExiste) return;

  const entregasSesion = entregas.filter(e => Number(e?.sesion || numero) === numero).map(e => ({
    id: e.id || generarId(),
    sesion: Number(e.sesion || numero),
    de: String(e.de ?? ''), para: String(e.para ?? ''),
    trigo: numeroNoNegativo(e.trigo, 0), hierro: numeroNoNegativo(e.hierro, 0),
    timestamp: e.timestamp || ahora()
  }));

  const produccionSesion = {};
  for (const [jugador, p] of Object.entries(produccion)) {
    produccionSesion[jugador] = {
      trigoInicial: p.trigoInicial ?? null,
      hierroInicial: p.hierroInicial ?? null,
      proceso: p.proceso ?? null,
      trigoProducido: p.trigoProducido ?? p.trigoProd ?? p.trigo ?? 0,
      hierroProducido: p.hierroProducido ?? p.hierroProd ?? p.hierro ?? 0,
      trigoFinal: p.trigoFinal ?? p.trigo ?? null,
      hierroFinal: p.hierroFinal ?? p.hierro ?? null,
    };
  }

  data.historialSesiones.push({
    numeroSesion: numero,
    iniciadaAt: entregasSesion[0]?.timestamp || data.createdAt,
    finalizadaAt: Object.values(produccion).length ? ahora() : (entregasSesion.at(-1)?.timestamp || ahora()),
    entregas: entregasSesion,
    produccion: produccionSesion,
  });
  data.historialSesiones.sort((a,b) => (Number(a.numeroSesion)||0) - (Number(b.numeroSesion)||0));
  data.updatedAt = ahora();
  await guardarHistorialPersistente(sala);
  await encolarGuardado();
  console.log(`Historial legado migrado para ${sala}: sesión ${numero}`);
}

async function recuperarHistorialesDesdeArchivos() {
  const histDir = path.join(__dirname, "historiales");
  if (!fs.existsSync(histDir)) return;

  let archivos = [];
  try {
    archivos = await fsp.readdir(histDir);
  } catch (err) {
    console.error("No se pudo leer la carpeta de historiales:", err);
    return;
  }

  // Compatibilidad con la antigua persistencia por archivos. El formato de
  // nombre puede variar entre versiones, así que buscamos primero por prefijo
  // y después extraemos la fecha final de forma tolerante.
  const grupos = new Map();
  for (const archivo of archivos) {
    if (!archivo.endsWith('.json')) continue;
    const tipo = archivo.startsWith('entregas_') ? 'entregas'
      : archivo.startsWith('produccion_') ? 'produccion' : null;
    if (!tipo) continue;

    const resto = archivo.slice((tipo + '_').length, -'.json'.length);
    const match = resto.match(/^(.*)_(\d{4}-\d{2}-\d{2}T.*)$/);
    if (!match) continue;

    const sala = saneaSala(match[1]);
    const marca = match[2].replace(/\.json$/, '');
    if (!salas[sala]) continue;

    const key = `${sala}|${marca}`;
    if (!grupos.has(key)) grupos.set(key, { sala, marca, entregas: [], produccion: {} });

    try {
      const raw = await fsp.readFile(path.join(histDir, archivo), 'utf8');
      const parsed = JSON.parse(raw);
      if (tipo === 'entregas') grupos.get(key).entregas = Array.isArray(parsed) ? parsed : [];
      else grupos.get(key).produccion = parsed && typeof parsed === 'object' ? parsed : {};
    } catch (err) {
      console.error(`No se pudo leer ${archivo}:`, err);
    }
  }

  for (const data of Object.values(salas)) {
    data.historialSesiones = Array.isArray(data.historialSesiones) ? data.historialSesiones : [];
  }

  // Solo rellenamos huecos: nunca sobrescribimos un historial que ya esté
  // correctamente almacenado dentro de estado_actual.json.
  const porSala = new Map();
  for (const grupo of grupos.values()) {
    if (!porSala.has(grupo.sala)) porSala.set(grupo.sala, []);
    porSala.get(grupo.sala).push(grupo);
  }

  let modificada = false;
  for (const [sala, gruposSala] of porSala.entries()) {
    const data = salas[sala];
    if (!data) continue;

    const existentes = new Set((data.historialSesiones || []).map(x => `${x.finalizadaAt}|${x.numeroSesion}`));
    gruposSala.sort((a, b) => a.marca.localeCompare(b.marca));

    for (const g of gruposSala) {
      const finalizadaAt = g.marca;
      if ([...existentes].some(k => k.startsWith(finalizadaAt + '|'))) continue;

      const numero = (data.historialSesiones.length ? Math.max(...data.historialSesiones.map(x => Number(x.numeroSesion) || 0)) : 0) + 1;
      const anterior = data.historialSesiones[data.historialSesiones.length - 1];
      data.historialSesiones.push({
        numeroSesion: numero,
        iniciadaAt: anterior?.finalizadaAt || data.createdAt,
        finalizadaAt,
        entregas: Array.isArray(g.entregas) ? g.entregas : [],
        produccion: g.produccion && typeof g.produccion === 'object' ? g.produccion : {},
      });
      modificada = true;
    }

    data.historialSesiones.sort((a, b) => (Number(a.numeroSesion) || 0) - (Number(b.numeroSesion) || 0));
  }

  if (modificada) {
    for (const data of Object.values(salas)) data.updatedAt = ahora();
    await encolarGuardado();
  }
}

function normalizarSala(sala) {
  const s = sala && typeof sala === "object" ? sala : {};

  s.adminPassword = typeof s.adminPassword === "string" ? s.adminPassword : "";
  s.adminId = null;
  s.adminSessionId = s.adminSessionId || null;

  s.config = {
    ...DEFAULT_CONFIG,
    ...(s.config || {}),
    informacionPublica: {
      ...DEFAULT_CONFIG.informacionPublica,
      ...((s.config && s.config.informacionPublica) || {}),
    },
  };

  s.fase = s.fase || (
    s.produccionAbierta ? "produccion" : "pausa"
  );
  // La fase "pausa" representa el intervalo entre cerrar producción y
  // abrir manualmente la siguiente sesión.
  if (!["entregas", "produccion", "pausa"].includes(s.fase)) s.fase = "entregas";

  s.numeroSesion = Number.isInteger(s.numeroSesion)
    ? s.numeroSesion
    : 1;

  s.jugadores = s.jugadores && typeof s.jugadores === "object"
    ? s.jugadores
    : {};
  s.nombresVisibles = s.nombresVisibles && typeof s.nombresVisibles === "object"
    ? s.nombresVisibles
    : {};

  for (const [nombre, jugador] of Object.entries(s.jugadores)) {
    s.jugadores[nombre] = normalizarJugador(jugador);
    if (!s.nombresVisibles[nombre]) s.nombresVisibles[nombre] = s.jugadores[nombre].nombreVisible || nombre;
  }

  s.historial = Array.isArray(s.historial) ? s.historial : [];
  s.historialSesiones = Array.isArray(s.historialSesiones) ? s.historialSesiones : [];
  s.historialEdicionesJugadores = Array.isArray(s.historialEdicionesJugadores) ? s.historialEdicionesJugadores : [];
  s.historialAuditoria = Array.isArray(s.historialAuditoria) ? s.historialAuditoria : [];
  s.sesionActualTiempos = s.sesionActualTiempos && typeof s.sesionActualTiempos === "object" ? s.sesionActualTiempos : {};
  s.sesionActualRecursosIniciales = s.sesionActualRecursosIniciales && typeof s.sesionActualRecursosIniciales === "object" ? s.sesionActualRecursosIniciales : {};

  // Corrige salas creadas con la versión que mostraba la primera sesión como 2.
  // Si aún no hay ninguna sesión cerrada, esa partida en curso es la sesión 1.
  if (s.numeroSesion === 2 && s.historialSesiones.length === 0) {
    s.numeroSesion = 1;
    s.historial = s.historial.map(e => ({ ...e, sesion: 1 }));
  }

  s.createdAt = s.createdAt || ahora();
  s.sesionActualIniciadaAt = s.sesionActualIniciadaAt || s.createdAt;
  s.updatedAt = s.updatedAt || ahora();

  // Compatibilidad con clientes antiguos.
  s.entregasAbiertas = s.fase === "entregas";
  s.produccionAbierta = s.fase === "produccion";

  return s;
}

function normalizarJugador(j) {
  const jugador = j && typeof j === "object" ? j : {};

  return {
    id: jugador.id || generarId(),
    password: typeof jugador.password === "string" ? jugador.password : "",
    nombreVisible: validaNombreVisible(jugador.nombreVisible, "") || "",
    trigo: numeroNoNegativo(jugador.trigo, 0),
    hierro: numeroNoNegativo(jugador.hierro, 0),
    entregas: Number.isInteger(jugador.entregas) && jugador.entregas >= 0
      ? jugador.entregas
      : 0,
    // Indica si ha alcanzado el máximo vigente. Se recalcula al cambiar el máximo.
    entregasMaximoAlcanzado: Boolean(jugador.entregasMaximoAlcanzado),
    proceso: [1, 2, 3].includes(jugador.proceso) ? jugador.proceso : null,
    trigoInsumo: numeroNoNegativo(jugador.trigoInsumo, numeroNoNegativo(jugador.trigo, 0)),
    hierroInsumo: numeroNoNegativo(jugador.hierroInsumo, numeroNoNegativo(jugador.hierro, 0)),
    trigoProd: numeroNoNegativo(jugador.trigoProd, 0),
    hierroProd: numeroNoNegativo(jugador.hierroProd, 0),
  };
}

// -----------------------------------------------------------------------------
// HISTORIAL
// -----------------------------------------------------------------------------

async function guardarHistorial(sala) {
  const data = salas[sala];
  if (!data) return;

  const histDir = path.join(__dirname, "historiales");
  await fsp.mkdir(histDir, { recursive: true });

  const fecha = ahora().replace(/[:.]/g, "-");

  const entregas = (data.historial || []).map((e) => ({ ...e }));

  const produccion = {};
  for (const [nombre, j] of Object.entries(data.jugadores)) {
    produccion[nombre] = {
      trigo: j.trigo,
      hierro: j.hierro,
      proceso: j.proceso,
      trigoProd: j.trigoProd,
      hierroProd: j.hierroProd,
    };
  }

  await writeAtomic(
    path.join(histDir, `entregas_${sala}_${fecha}.json`),
    JSON.stringify(entregas, null, 2)
  );

  await writeAtomic(
    path.join(histDir, `produccion_${sala}_${fecha}.json`),
    JSON.stringify(produccion, null, 2)
  );
}

// -----------------------------------------------------------------------------
// ESTADO PÚBLICO
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// HISTORIAL PÚBLICO DE SESIONES
// -----------------------------------------------------------------------------

function historialSesionesPublico(data, socket) {
  const esAdmin = socket.data.rol === "admin" && data.adminId === socket.id;
  const esJugador = socket.data.rol === "jugador";

  return (data.historialSesiones || []).map((sesion) => {
    // El historial estructurado es común para administrador, jugadores y
    // superadministrador. Las restricciones de privacidad de la vista actual
    // siguen aplicándose al estado en vivo, no al registro histórico.
    const entregas = (sesion.entregas || []).map(e => ({ ...e }));
    if (!esAdmin && !esJugador && socket.data.rol !== "superadmin") return null;

    const produccion = {};
    for (const [jugador, p] of Object.entries(sesion.produccion || {})) {
      produccion[jugador] = { ...p };
    }

    return {
      numeroSesion: sesion.numeroSesion,
      iniciadaAt: sesion.iniciadaAt,
      entregasAbiertasAt: sesion.entregasAbiertasAt || sesion.tiempos?.entregasAbiertasAt || sesion.iniciadaAt || null,
      entregasCerradasAt: sesion.entregasCerradasAt || sesion.tiempos?.entregasCerradasAt || null,
      produccionAbiertaAt: sesion.produccionAbiertaAt || sesion.tiempos?.produccionAbiertaAt || null,
      produccionCerradaAt: sesion.produccionCerradaAt || sesion.tiempos?.produccionCerradaAt || sesion.finalizadaAt || null,
      finalizadaAt: sesion.finalizadaAt,
      tiempos: copiar(sesion.tiempos || {}),
      recursosIniciales: copiar(sesion.recursosIniciales || {}),
      recursosDespuesEntregas: copiar(sesion.recursosDespuesEntregas || {}),
      entregas,
      produccion,
      auditoria: copiar(sesion.auditoria || []),
    };
  }).filter(Boolean);
}


function jugadorPublico(j, mostrarPassword = false) {
  if (!j) return null;

  const salida = {
    id: j.id,
    trigo: j.trigo,
    hierro: j.hierro,
    entregas: j.entregas,
    proceso: j.proceso,
    trigoInsumo: j.trigoInsumo,
    hierroInsumo: j.hierroInsumo,
    trigoProd: j.trigoProd,
    hierroProd: j.hierroProd,
    nombreVisible: j.nombreVisible || "",
  };

  // Nunca se utiliza en el estado enviado a otros clientes.
  if (mostrarPassword) salida.password = undefined;

  return salida;
}

function estadoPublico(sala, socket) {
  const data = salas[sala];
  if (!data) return null;

  const rol = socket.data.rol || "viewer";
  const nombre = socket.data.nombreJugador || null;
  const esAdmin = rol === "admin" && data.adminId === socket.id;

  const jugadores = {};

  for (const [nombreJugador, jugador] of Object.entries(data.jugadores)) {
    const esPropio = nombreJugador === nombre;

    // Las cantidades de los demás pueden ser ocultadas por configuración.
    const puedeVerCantidades =
      esAdmin ||
      esPropio ||
      data.config.informacionPublica.cantidadesJugadores;

    const pj = jugadorPublico(jugador);

    if (!puedeVerCantidades) {
      delete pj.trigo;
      delete pj.hierro;
      delete pj.trigoInsumo;
      delete pj.hierroInsumo;
      delete pj.trigoProd;
      delete pj.hierroProd;
    }

    if (!data.config.informacionPublica.procesosElegidos && !esAdmin && !esPropio) {
      pj.proceso = null;
    }

    jugadores[nombreJugador] = pj;
  }

  const historial = data.config.informacionPublica.entregasGlobales || esAdmin
    ? data.historial.map((e) => ({ ...e }))
    : data.historial.filter((e) => e.de === nombre || e.para === nombre).map((e) => ({ ...e }));

  return {
    sala,
    fase: data.fase,
    // Compatibilidad con la interfaz antigua.
    entregasAbiertas: data.fase === "entregas",
    produccionAbierta: data.fase === "produccion",

    numeroSesion: data.numeroSesion,
    config: copiar(data.config),
    jugadores,
    nombresVisibles: { ...(data.nombresVisibles || {}) },
    historial,
    historialSesiones: historialSesionesPublico(data, socket),

    // Identidad útil para las interfaces.
    yo: nombre,
    rol,
    esAdmin,

    // El ID del socket nunca se considera una identidad persistente.
    updatedAt: data.updatedAt,
  };
}

function emitirEstado(sala) {
  const data = salas[sala];
  if (!data) return;

  io.in(sala).fetchSockets().then((sockets) => {
    for (const socket of sockets) {
      const publico = estadoPublico(sala, socket);
      socket.emit("actualizarEstado", publico);
    }
  }).catch((err) => {
    console.error("Error al emitir estado:", err);
  });
}

// -----------------------------------------------------------------------------
// AUTORIZACIÓN
// -----------------------------------------------------------------------------

function obtenerSalaDesdeSocket(socket, sala) {
  const nombreSala = saneaSala(sala);

  if (!nombreSala) {
    respuestaError(socket, "Nombre de sala no válido", "SALA_INVALIDA");
    return null;
  }

  const data = salas[nombreSala];

  if (!data) {
    respuestaError(socket, "Sala no encontrada", "SALA_NO_ENCONTRADA");
    return null;
  }

  if (socket.data.sala !== nombreSala) {
    respuestaError(socket, "No estás autenticado en esta sala", "NO_AUTENTICADO");
    return null;
  }

  return data;
}

function exigirAdmin(socket, sala) {
  const data = obtenerSalaDesdeSocket(socket, sala);

  if (!data) return null;

  if (socket.data.rol !== "admin" || data.adminId !== socket.id) {
    respuestaError(socket, "Acción restringida al administrador", "SOLO_ADMIN");
    return null;
  }

  return data;
}

function exigirJugador(socket, sala) {
  const data = obtenerSalaDesdeSocket(socket, sala);

  if (!data) return null;

  if (socket.data.rol !== "jugador" || !socket.data.nombreJugador) {
    respuestaError(socket, "Acción restringida a jugadores", "SOLO_JUGADOR");
    return null;
  }

  const jugador = data.jugadores[socket.data.nombreJugador];

  if (!jugador) {
    respuestaError(socket, "Jugador no encontrado", "JUGADOR_NO_ENCONTRADO");
    return null;
  }

  return { data, jugador, nombre: socket.data.nombreJugador };
}

// -----------------------------------------------------------------------------
// SUPERADMIN
// -----------------------------------------------------------------------------

function resumenSalasSuperadmin() {
  return Object.entries(salas)
    .map(([nombre, data]) => ({
      sala: nombre,
      creadaAt: data.createdAt || null,
      actualizadaAt: data.updatedAt || null,
      fase: data.fase || null,
      numeroSesion: data.numeroSesion || 1,
      jugadores: Object.keys(data.jugadores || {}).length,
      maxEntregas: data.config?.maxEntregas ?? DEFAULT_CONFIG.maxEntregas,
      tipoJuego: data.config?.tipoJuego ?? DEFAULT_CONFIG.tipoJuego,
    }))
    .sort((a, b) => a.sala.localeCompare(b.sala, "es"));
}


function resumenExperimentosSuperadmin() {
  const experimentos = [];

  for (const [nombreSala, data] of Object.entries(salas)) {
    const jugadores = data.jugadores || {};
    const producciones = data.producciones || data.historialProducciones || {};
    const entregas = Array.isArray(data.entregas) ? data.entregas : [];

    // Las sesiones históricas pueden variar entre versiones.
    const sesiones = Array.isArray(data.historialSesiones)
      ? data.historialSesiones
      : Array.isArray(data.sesiones)
        ? data.sesiones
        : [];

    const sesionesRealizadas = sesiones.length
      ? sesiones.length
      : Math.max(0, Number(data.numeroSesion || 1) - 1);

    // Una sala se considera terminada cuando tiene al menos una sesión cerrada.
    const terminado = sesionesRealizadas > 0;

    experimentos.push({
      sala: nombreSala,
      terminado,
      participantes: Object.keys(jugadores).length,
      sesionesRealizadas,
      totalEntregas: entregas.length,
      totalProducciones: Object.keys(producciones).length,
      creadaAt: data.createdAt || null,
      actualizadaAt: data.updatedAt || null
    });
  }

  return experimentos.sort((a, b) => a.sala.localeCompare(b.sala, "es"));
}

function datosExperimentoSuperadmin(nombreSala) {
  const data = salas[nombreSala];
  if (!data) return null;

  const jugadores = data.jugadores || {};
  const entregas = Array.isArray(data.entregas) ? data.entregas : [];
  const producciones = data.producciones || data.historialProducciones || {};

  const sesiones = Array.isArray(data.historialSesiones)
    ? data.historialSesiones
    : Array.isArray(data.sesiones)
      ? data.sesiones
      : [];

  return {
    sala: nombreSala,
    participantes: Object.keys(jugadores).length,
    sesionesRealizadas: sesiones.length || Math.max(0, Number(data.numeroSesion || 1) - 1),
    entregas: JSON.parse(JSON.stringify(entregas)),
    producciones: JSON.parse(JSON.stringify(producciones)),
    sesiones: JSON.parse(JSON.stringify(sesiones)),
    ediciones: JSON.parse(JSON.stringify(data.historialEdicionesJugadores || [])),
    auditoria: JSON.parse(JSON.stringify(data.historialAuditoria || [])),
    nombresVisibles: JSON.parse(JSON.stringify(data.nombresVisibles || {}))
  };
}

function exigirSuperadmin(socket) {
  if (!SUPERADMIN_PASSWORD) {
    respuestaError(
      socket,
      "La consola de superadministrador está desactivada. Define SUPERADMIN_PASSWORD en el entorno del servidor.",
      "SUPERADMIN_DESACTIVADO"
    );
    return false;
  }

  if (socket.data.rol !== "superadmin") {
    respuestaError(socket, "No estás autenticado como superadministrador", "SUPERADMIN_NO_AUTENTICADO");
    return false;
  }

  return true;
}


// -----------------------------------------------------------------------------
// HISTORIAL DE EDICIONES DE JUGADORES
// -----------------------------------------------------------------------------

function historialEdicionesJugadoresPublico(data, socket) {
  const autenticadoEnSala = socket.data.sala === socket.data.sala &&
    (socket.data.rol === "jugador" || (socket.data.rol === "admin" && data.adminId === socket.id));
  if (!autenticadoEnSala) return [];
  return (data.historialEdicionesJugadores || []).map((e) => ({ ...e }));
}

// -----------------------------------------------------------------------------
// SOCKET.IO
// -----------------------------------------------------------------------------

io.on("connection", (socket) => {
  console.log("Usuario conectado:", socket.id);

  // ---------------------------------------------------------------------------
  // SUPERADMIN
  // ---------------------------------------------------------------------------

  socket.on("entrarSuperadmin", (password) => {
    if (!SUPERADMIN_PASSWORD) {
      return respuestaError(
        socket,
        "La consola de superadministrador está desactivada en este servidor.",
        "SUPERADMIN_DESACTIVADO"
      );
    }

    if (typeof password !== "string" || password !== SUPERADMIN_PASSWORD) {
      return respuestaError(socket, "Contraseña de superadministrador incorrecta", "LOGIN_SUPERADMIN");
    }

    socket.data.rol = "superadmin";
    socket.data.sala = null;
    socket.data.nombreJugador = null;

    socket.emit("superadminEntrado", {
      salas: resumenSalasSuperadmin(),
    });
  });

  socket.on("superadminListarSalas", () => {
    if (!exigirSuperadmin(socket)) return;
    socket.emit("salasSuperadmin", resumenSalasSuperadmin());
  });

  // ---------------------------------------------------------------------------
  // CONSULTA DE EXPERIMENTOS DEL SUPERADMIN
  // ---------------------------------------------------------------------------

  socket.on("superadminListarExperimentos", () => {
    if (!exigirSuperadmin(socket)) return;
    socket.emit("experimentosSuperadmin", resumenExperimentosSuperadmin());
  });

  socket.on("superadminVerExperimento", (nombreSala) => {
    if (!exigirSuperadmin(socket)) return;
    if (typeof nombreSala !== "string" || !salas[nombreSala]) {
      return respuestaError(socket, "La sala solicitada no existe", "SALA_NO_ENCONTRADA");
    }

    socket.emit("experimentoSuperadmin", datosExperimentoSuperadmin(nombreSala));
  });

  // ---------------------------------------------------------------------------
  // CREAR SALA
  // ---------------------------------------------------------------------------

  socket.on("crearSala", async ({ sala, password } = {}) => {
    try {
      const nombreSala = saneaSala(sala);

      if (!nombreSala) {
        return respuestaError(socket, "Nombre de sala no válido", "SALA_INVALIDA");
      }

      if (!validaPassword(password)) {
        return respuestaError(socket, "Contraseña no válida", "PASSWORD_INVALIDA");
      }

      if (salas[nombreSala]) {
        return socket.emit("salaExiste");
      }

      const passwordHash = await hashPassword(password);

      salas[nombreSala] = normalizarSala({
        adminPassword: passwordHash,
        adminId: null,
        adminSessionId: null,
        jugadores: {},
        historial: [],
        historialSesiones: [],
        historialEdicionesJugadores: [],
        historialAuditoria: [],
        nombresVisibles: {},
        sesionActualIniciadaAt: ahora(),
        sesionActualTiempos: {},
        sesionActualRecursosIniciales: {},
        fase: "pausa",
        numeroSesion: 1,
        config: copiar(DEFAULT_CONFIG),
        createdAt: ahora(),
        updatedAt: ahora(),
      });

      await encolarGuardado();

      socket.emit("salaCreada", nombreSala);
      console.log(`Sala creada: ${nombreSala}`);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo crear la sala", "ERROR_CREAR_SALA");
    }
  });

  // ---------------------------------------------------------------------------
  // ENTRAR ADMIN
  // ---------------------------------------------------------------------------

  socket.on("entrarAdmin", async ({ sala, password } = {}) => {
    try {
      const nombreSala = saneaSala(sala);
      const data = salas[nombreSala];

      if (!data || !validaPassword(password)) {
        // No revelamos contraseñas ni información adicional. Solo mostramos
        // los nombres de las salas existentes para facilitar la elección.
        socket.emit("salasDisponibles", Object.keys(salas).sort((a, b) => a.localeCompare(b, "es")));
        return respuestaError(socket, "Sala o contraseña incorrecta", "LOGIN_ADMIN");
      }

      const correcto = await verificarYActualizarPassword(password, data.adminPassword);

      if (!correcto) {
        socket.emit("salasDisponibles", Object.keys(salas).sort((a, b) => a.localeCompare(b, "es")));
        return respuestaError(socket, "Sala o contraseña incorrecta", "LOGIN_ADMIN");
      }

      // Migración automática de contraseñas antiguas.
      if (!data.adminPassword.startsWith("scrypt$")) {
        data.adminPassword = await hashPassword(password);
      }

      // Si había otro socket de administrador, la nueva autenticación toma
      // el control. La partida no se pierde.
      data.adminId = socket.id;
      data.adminSessionId = data.adminSessionId || generarId();

      socket.data.sala = nombreSala;
      socket.data.rol = "admin";
      socket.data.nombreJugador = null;
      socket.data.adminSessionId = data.adminSessionId;

      socket.join(nombreSala);

      data.updatedAt = ahora();
      await encolarGuardado();

      socket.emit("adminEntrado", nombreSala);
      socket.emit("historialSesiones", historialSesionesPublico(data, socket));
      emitirEstado(nombreSala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo iniciar sesión como administrador", "LOGIN_ADMIN");
    }
  });

  // ---------------------------------------------------------------------------
  // CREAR JUGADOR
  // ---------------------------------------------------------------------------

  socket.on("crearJugador", async ({ sala, nombre, nombreVisible, password, trigo, hierro } = {}) => {
    try {
      const nombreSala = saneaSala(sala);
      const data = salas[nombreSala];

      if (!data) return respuestaError(socket, "Sala no encontrada", "SALA_NO_ENCONTRADA");

      // La creación/importación de jugadores debe hacerla el administrador.
      if (socket.data.sala !== nombreSala ||
          socket.data.rol !== "admin" ||
          data.adminId !== socket.id) {
        return respuestaError(socket, "Solo el administrador puede crear jugadores", "SOLO_ADMIN");
      }

      const nombreJugador = validaNombreJugador(nombre);

      if (!nombreJugador) {
        return respuestaError(socket, "Nombre de jugador no válido", "NOMBRE_INVALIDO");
      }

      if (!validaPassword(password)) {
        return respuestaError(socket, "Contraseña de jugador no válida", "PASSWORD_INVALIDA");
      }

      const nombreVisibleJugador = validaNombreVisible(nombreVisible, nombreJugador);
      if (!nombreVisibleJugador) {
        return respuestaError(socket, "Nombre visible no válido", "NOMBRE_VISIBLE_INVALIDO");
      }

      if (data.jugadores[nombreJugador]) {
        return respuestaError(socket, "Jugador ya existe", "JUGADOR_EXISTE");
      }

      const trigoN = numeroNoNegativo(trigo, 0);
      const hierroN = numeroNoNegativo(hierro, 0);

      data.jugadores[nombreJugador] = {
        id: generarId(),
        password: await hashPassword(password),
        nombreVisible: nombreVisibleJugador,
        trigo: trigoN,
        hierro: hierroN,
        entregas: 0,
        entregasMaximoAlcanzado: false,
        proceso: null,
        produccionAt: null,
        trigoInsumo: trigoN,
        hierroInsumo: hierroN,
        trigoProd: 0,
        hierroProd: 0,
      };

      data.nombresVisibles[nombreJugador] = nombreVisibleJugador;
      registrarAuditoria(data, "altaJugador", {
        accion: "Alta",
        usuario: nombreJugador,
        posterior: snapshotJugador(nombreJugador, data.jugadores[nombreJugador], "—"),
      });
      data.updatedAt = ahora();

      await encolarGuardado();
      emitirEstado(nombreSala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo crear el jugador", "ERROR_CREAR_JUGADOR");
    }
  });

  // ---------------------------------------------------------------------------
  // ENTRAR JUGADOR / VIEWER
  // ---------------------------------------------------------------------------

  socket.on("entrarJugador", async ({ sala, nombre, password } = {}) => {
    try {
      const nombreSala = saneaSala(sala);
      const data = salas[nombreSala];

      if (!data) {
        return respuestaError(socket, "Sala no encontrada", "SALA_NO_ENCONTRADA");
      }

      // El viewer es un rol explícito, no una identidad de jugador.
      if (nombre === "__viewer__") {
        socket.data.sala = nombreSala;
        socket.data.rol = "viewer";
        socket.data.nombreJugador = null;
        socket.join(nombreSala);

        socket.emit("jugadorEntrado", {
          sala: nombreSala,
          nombre: "__viewer__",
        });

        return emitirEstado(nombreSala);
      }

      const nombreJugador = validaNombreJugador(nombre);
      const jugador = nombreJugador ? data.jugadores[nombreJugador] : null;

      if (!jugador || !validaPassword(password)) {
        return respuestaError(
          socket,
          "Sala o jugador no encontrado o contraseña incorrecta",
          "LOGIN_JUGADOR"
        );
      }

      const correcto = await verificarYActualizarPassword(password, jugador.password);

      if (!correcto) {
        return respuestaError(
          socket,
          "Sala o jugador no encontrado o contraseña incorrecta",
          "LOGIN_JUGADOR"
        );
      }

      if (!jugador.password.startsWith("scrypt$")) {
        jugador.password = await hashPassword(password);
        data.updatedAt = ahora();
        await encolarGuardado();
      }

      socket.data.sala = nombreSala;
      socket.data.rol = "jugador";
      socket.data.nombreJugador = nombreJugador;

      socket.join(nombreSala);

      socket.emit("jugadorEntrado", {
        sala: nombreSala,
        nombre: nombreJugador,
        nombreVisible: jugador.nombreVisible || nombreJugador,
      });
      socket.emit("historialSesiones", historialSesionesPublico(data, socket));

      emitirEstado(nombreSala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo iniciar sesión", "LOGIN_JUGADOR");
    }
  });

  // ---------------------------------------------------------------------------
  // CAMBIAR CONTRASEÑA DEL JUGADOR
  // ---------------------------------------------------------------------------

  socket.on("cambiarPasswordJugador", async ({ sala, actual, nueva, confirmacion } = {}) => {
    try {
      const contexto = exigirJugador(socket, sala);
      if (!contexto) return;

      const { data, jugador } = contexto;

      if (!validaPassword(actual) || !validaPassword(nueva) || !validaPassword(confirmacion)) {
        return respuestaError(socket, "Las contraseñas no son válidas", "PASSWORD_INVALIDA");
      }

      if (nueva !== confirmacion) {
        return respuestaError(socket, "La nueva contraseña no coincide", "PASSWORD_NO_COINCIDE");
      }

      const correcto = await verificarYActualizarPassword(actual, jugador.password);
      if (!correcto) {
        return respuestaError(socket, "La contraseña actual es incorrecta", "PASSWORD_ACTUAL_INCORRECTA");
      }

      jugador.password = await hashPassword(nueva);
      data.updatedAt = ahora();
      await encolarGuardado();
      socket.emit("passwordCambiada");
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo cambiar la contraseña", "ERROR_CAMBIAR_PASSWORD");
    }
  });

  // ---------------------------------------------------------------------------
  // RESTABLECER CONTRASEÑA DE JUGADOR (ADMIN)
  // ---------------------------------------------------------------------------

  socket.on("restablecerPasswordJugador", async ({ sala, nombre, nueva } = {}) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      const nombreJugador = validaNombreJugador(nombre);
      const jugador = nombreJugador ? data.jugadores[nombreJugador] : null;

      if (!jugador) {
        return respuestaError(socket, "Jugador no encontrado", "JUGADOR_NO_ENCONTRADO");
      }

      if (!validaPassword(nueva)) {
        return respuestaError(socket, "La nueva contraseña no es válida", "PASSWORD_INVALIDA");
      }

      jugador.password = await hashPassword(nueva);
      registrarAuditoria(data, "cambioPasswordAdministrador", {
        accion: "Restablecimiento de contraseña",
        usuario: nombreJugador,
        posterior: { usuario: nombreJugador, contraseña: "actualizada" },
      });
      data.updatedAt = ahora();
      await encolarGuardado();
      socket.emit("passwordRestablecida", { nombre: nombreJugador });
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo restablecer la contraseña", "ERROR_RESTABLECER_PASSWORD");
    }
  });

  // ---------------------------------------------------------------------------
  // EDITAR JUGADOR (ADMIN)
  // ---------------------------------------------------------------------------

  function snapshotJugador(nombre, jugador, passwordEstado = "—") {
    return {
      usuario: nombre || "—",
      nombreVisible: jugador?.nombreVisible || nombre || "—",
      trigo: Number(jugador?.trigo) || 0,
      hierro: Number(jugador?.hierro) || 0,
      entregas: Number(jugador?.entregas) || 0,
      proceso: jugador?.proceso ?? null,
      contraseña: passwordEstado,
    };
  }

  socket.on("editarJugador", async ({ sala, original, nombre, nombreVisible, password, trigo, hierro, entregas, proceso } = {}) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      const nombreOriginal = validaNombreJugador(original);
      const jugador = nombreOriginal ? data.jugadores[nombreOriginal] : null;
      if (!jugador) {
        return respuestaError(socket, "Jugador no encontrado", "JUGADOR_NO_ENCONTRADO");
      }

      const nuevoNombre = validaNombreJugador(nombre);
      if (!nuevoNombre) return respuestaError(socket, "Usuario no válido", "NOMBRE_INVALIDO");
      if (nuevoNombre !== nombreOriginal && data.jugadores[nuevoNombre]) {
        return respuestaError(socket, "Ese usuario ya existe", "JUGADOR_EXISTE");
      }

      const nuevoVisible = validaNombreVisible(nombreVisible, nuevoNombre);
      if (!nuevoVisible) return respuestaError(socket, "Nombre visible no válido", "NOMBRE_VISIBLE_INVALIDO");

      const trigoN = numeroNoNegativo(trigo, 0);
      const hierroN = numeroNoNegativo(hierro, 0);
      const entregasN = Number(entregas);
      if (!Number.isInteger(entregasN) || entregasN < 0) {
        return respuestaError(socket, "Número de entregas no válido", "ENTREGAS_INVALIDAS");
      }
      if (proceso !== null && proceso !== undefined && proceso !== "" && ![1, 2, 3].includes(Number(proceso))) {
        return respuestaError(socket, "Proceso no válido", "PROCESO_INVALIDO");
      }

      const procesoN = proceso === null || proceso === undefined || proceso === "" ? null : Number(proceso);
      if (password !== undefined && String(password) !== "" && !validaPassword(String(password))) {
        return respuestaError(socket, "Contraseña no válida", "PASSWORD_INVALIDA");
      }

      const passwordCambiada = password !== undefined && String(password) !== "";
      const snapshotAnterior = snapshotJugador(nombreOriginal, jugador, "—");
      const cambios = [];
      if (nombreOriginal !== nuevoNombre) cambios.push({ campo: "Usuario", antes: nombreOriginal, despues: nuevoNombre });
      const visibleAnterior = jugador.nombreVisible || nombreOriginal;
      if (visibleAnterior !== nuevoVisible) cambios.push({ campo: "Nombre visible", antes: visibleAnterior, despues: nuevoVisible });
      if (Number(jugador.trigo) !== trigoN) cambios.push({ campo: "Trigo", antes: Number(jugador.trigo) || 0, despues: trigoN });
      if (Number(jugador.hierro) !== hierroN) cambios.push({ campo: "Hierro", antes: Number(jugador.hierro) || 0, despues: hierroN });
      if (Number(jugador.entregas) !== entregasN) cambios.push({ campo: "Entregas", antes: Number(jugador.entregas) || 0, despues: entregasN });
      const procesoAnterior = jugador.proceso ?? null;
      if (procesoAnterior !== procesoN) cambios.push({ campo: "Proceso", antes: procesoAnterior, despues: procesoN });
      if (passwordCambiada) cambios.push({ campo: "Contraseña", antes: "—", despues: "actualizada" });

      jugador.nombreVisible = nuevoVisible;
      jugador.trigo = trigoN;
      jugador.hierro = hierroN;
      jugador.entregas = entregasN;
      jugador.entregasMaximoAlcanzado = data.config.maxEntregas >= 0 && entregasN >= data.config.maxEntregas;
      jugador.proceso = procesoN;
      jugador.trigoInsumo = Number.isFinite(Number(jugador.trigoInsumo)) ? jugador.trigoInsumo : trigoN;
      jugador.hierroInsumo = Number.isFinite(Number(jugador.hierroInsumo)) ? jugador.hierroInsumo : hierroN;
      if (password !== undefined && String(password) !== "") jugador.password = await hashPassword(String(password));

      if (nuevoNombre !== nombreOriginal) {
        delete data.jugadores[nombreOriginal];
        data.jugadores[nuevoNombre] = jugador;
        // Si hay una sesión abierta, el recurso inicial debe seguir al jugador
        // aunque cambie su nombre durante la sesión.
        if (data.sesionActualRecursosIniciales?.[nombreOriginal]) {
          data.sesionActualRecursosIniciales[nuevoNombre] = data.sesionActualRecursosIniciales[nombreOriginal];
          delete data.sesionActualRecursosIniciales[nombreOriginal];
        }
        if (data.sesionActualRecursosDespuesEntregas?.[nombreOriginal]) {
          data.sesionActualRecursosDespuesEntregas[nuevoNombre] = data.sesionActualRecursosDespuesEntregas[nombreOriginal];
          delete data.sesionActualRecursosDespuesEntregas[nombreOriginal];
        }
        // Conservamos el alias anterior para que el historial siga pudiendo
        // resolver correctamente las acciones realizadas con el usuario antiguo.
        data.nombresVisibles[nombreOriginal] = jugador.nombreVisible || nuevoVisible;
      }
      data.nombresVisibles[nuevoNombre] = nuevoVisible;
      data.updatedAt = ahora();

      if (cambios.length) {
        const snapshotPosterior = snapshotJugador(
          nuevoNombre,
          jugador,
          passwordCambiada ? "actualizada" : "—"
        );
        data.historialEdicionesJugadores.push({
          id: generarId(),
          timestamp: data.updatedAt,
          sesion: sesionObjetivoAuditoria(data),
          accion: "Edición",
          usuario: nuevoNombre,
          nombreVisible: nuevoVisible,
          usuarioAnterior: nombreOriginal,
          nombreVisibleAnterior: visibleAnterior,
          anterior: snapshotAnterior,
          posterior: snapshotPosterior,
          cambios,
          realizadoPor: "Administrador",
        });
      }

      await encolarGuardado();

      // Si el jugador estaba conectado, actualizamos su usuario sin expulsarlo.
      if (nuevoNombre !== nombreOriginal) {
        const sockets = await io.in(sala).fetchSockets();
        for (const cliente of sockets) {
          if (cliente.data.rol === "jugador" && cliente.data.nombreJugador === nombreOriginal) {
            cliente.data.nombreJugador = nuevoNombre;
          }
        }
      }

      emitirEstado(sala);
      socket.emit("jugadorEditado", { original: nombreOriginal, nombre: nuevoNombre });
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo editar el jugador", "ERROR_EDITAR_JUGADOR");
    }
  });

  // ---------------------------------------------------------------------------
  // ELIMINAR JUGADOR (ADMIN)
  // ---------------------------------------------------------------------------

  socket.on("eliminarJugador", async ({ sala, nombre } = {}) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      const nombreJugador = validaNombreJugador(nombre);
      const jugador = nombreJugador ? data.jugadores[nombreJugador] : null;
      if (!jugador) {
        return respuestaError(socket, "Jugador no encontrado", "JUGADOR_NO_ENCONTRADO");
      }

      // Conservamos su nombre visible para que las acciones históricas sigan
      // identificándolo aunque ya no forme parte de los jugadores activos.
      const snapshotAnterior = snapshotJugador(nombreJugador, jugador, "—");
      const timestampEliminacion = ahora();
      data.nombresVisibles[nombreJugador] = jugador.nombreVisible || nombreJugador;
      delete data.jugadores[nombreJugador];
      data.historialEdicionesJugadores.push({
        id: generarId(),
        timestamp: timestampEliminacion,
        sesion: sesionObjetivoAuditoria(data),
        accion: "Eliminación",
        usuario: "—",
        nombreVisible: "—",
        usuarioAnterior: nombreJugador,
        nombreVisibleAnterior: snapshotAnterior.nombreVisible,
        anterior: snapshotAnterior,
        posterior: { usuario: "—", nombreVisible: "—", trigo: "—", hierro: "—", entregas: "—", proceso: "—", contraseña: "—" },
        cambios: [
          { campo: "Jugador", antes: nombreJugador, despues: "Eliminado" }
        ],
        realizadoPor: "Administrador",
      });
      registrarAuditoria(data, "eliminacionJugador", {
        accion: "Eliminación",
        usuarioAnterior: nombreJugador,
        anterior: snapshotAnterior,
        cambios: [{ campo: "Jugador", antes: nombreJugador, despues: "Eliminado" }],
      });
      data.updatedAt = timestampEliminacion;
      await encolarGuardado();

      // Expulsamos sus conexiones activas de esta sala, si las hubiera.
      const sockets = await io.in(sala).fetchSockets();
      for (const cliente of sockets) {
        if (cliente.data.rol === "jugador" && cliente.data.nombreJugador === nombreJugador) {
          cliente.emit("jugadorEliminado");
          cliente.disconnect(true);
        }
      }

      emitirEstado(sala);
      socket.emit("jugadorEliminadoAdmin", { nombre: nombreJugador });
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo eliminar el jugador", "ERROR_ELIMINAR_JUGADOR");
    }
  });

  // ---------------------------------------------------------------------------
  // IMPORTAR JUGADORES
  // ---------------------------------------------------------------------------

  socket.on("importarJugadores", async ({ sala, jugadores } = {}) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      if (!Array.isArray(jugadores)) {
        return respuestaError(socket, "Formato de jugadores incorrecto", "IMPORT_FORMATO");
      }

      for (const entrada of jugadores) {
        const nombre = validaNombreJugador(entrada?.nombre);
        if (!nombre || data.jugadores[nombre]) continue;

        const password = String(entrada?.password ?? "");
        if (!validaPassword(password)) continue;

        const nombreVisible = validaNombreVisible(entrada?.nombre_visible ?? entrada?.nombreVisible, nombre);
        if (!nombreVisible) continue;

        const trigoN = numeroNoNegativo(entrada?.trigo, 0);
        const hierroN = numeroNoNegativo(entrada?.hierro, 0);

        data.jugadores[nombre] = {
          id: generarId(),
          password: await hashPassword(password),
          nombreVisible,
          trigo: trigoN,
          hierro: hierroN,
          entregas: Number.isInteger(entrada?.entregas) && entrada.entregas >= 0
            ? entrada.entregas
            : 0,
          entregasMaximoAlcanzado: false,
          proceso: null,
          trigoInsumo: trigoN,
          hierroInsumo: hierroN,
          trigoProd: 0,
          hierroProd: 0,
        };
        data.nombresVisibles[nombre] = nombreVisible;
        registrarAuditoria(data, "altaJugador", {
          accion: "Alta",
          usuario: nombre,
          posterior: snapshotJugador(nombre, data.jugadores[nombre], "—"),
        });
      }

      data.updatedAt = ahora();
      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudieron importar los jugadores", "ERROR_IMPORTAR");
    }
  });

  // ---------------------------------------------------------------------------
  // CONFIGURACIÓN DE SALA
  // ---------------------------------------------------------------------------

  socket.on("configurarSala", async ({ sala, config } = {}) => {
    const data = exigirAdmin(socket, sala);
    if (!data) return;

    if (!config || typeof config !== "object") {
      return respuestaError(socket, "Configuración no válida", "CONFIG_INVALIDA");
    }

    const configAntes = copiar(data.config);

    if (config.maxEntregas !== undefined) {
      const max = Number(config.maxEntregas);
      if (!Number.isInteger(max) || max < 0 || max > 1000) {
        return respuestaError(socket, "Número máximo de entregas no válido", "MAX_ENTREGAS_INVALIDO");
      }
      const maxAnterior = Number(data.config.maxEntregas);
      data.config.maxEntregas = max;
      if (max !== maxAnterior) {
        for (const jugador of Object.values(data.jugadores || {})) {
          jugador.entregasMaximoAlcanzado = max >= 0 && Number(jugador.entregas) >= max;
        }
      }
    }

    if (typeof config.tipoJuego === "string") {
      const permitidos = ["capital", "anarquia", "plan"];
      if (!permitidos.includes(config.tipoJuego)) {
        return respuestaError(socket, "Tipo de juego no válido", "TIPO_JUEGO_INVALIDO");
      }
      data.config.tipoJuego = config.tipoJuego;
    }

    if (config.informacionPublica && typeof config.informacionPublica === "object") {
      for (const clave of Object.keys(DEFAULT_CONFIG.informacionPublica)) {
        if (config.informacionPublica[clave] !== undefined) {
          data.config.informacionPublica[clave] =
            Boolean(config.informacionPublica[clave]);
        }
      }
    }

    const configDespues = copiar(data.config);
    if (JSON.stringify(configAntes) !== JSON.stringify(configDespues)) {
      registrarAuditoria(data, "configuracion", {
        accion: "Configuración",
        anterior: configAntes,
        posterior: configDespues,
      });
    }
    data.updatedAt = ahora();
    await encolarGuardado();
    emitirEstado(sala);
  });

  // ---------------------------------------------------------------------------
  // ENVIAR ENTREGA
  // ---------------------------------------------------------------------------

  socket.on("enviarEntrega", async ({ sala, para, trigo, hierro } = {}) => {
    try {
      const contexto = exigirJugador(socket, sala);
      if (!contexto) return;

      const { data, jugador: emisor, nombre: de } = contexto;

      if (data.fase !== "entregas") {
        return respuestaError(socket, "Las entregas están cerradas", "FASE_INCORRECTA");
      }

      if (data.config.maxEntregas >= 0 && emisor.entregas >= data.config.maxEntregas) {
        emisor.entregasMaximoAlcanzado = true;
        return respuestaError(
          socket,
          `Has alcanzado el máximo de ${data.config.maxEntregas} entregas de esta sesión.`,
          "MAX_ENTREGAS"
        );
      }
      // Si el administrador amplió el máximo, un jugador que había alcanzado
      // el límite anterior vuelve a estar habilitado automáticamente.
      emisor.entregasMaximoAlcanzado = false;

      const receptorNombre = validaNombreJugador(para);
      const receptor = receptorNombre ? data.jugadores[receptorNombre] : null;

      if (!receptor) {
        return respuestaError(socket, "Jugador receptor no encontrado", "RECEPTOR_NO_ENCONTRADO");
      }

      if (receptorNombre === de) {
        return respuestaError(socket, "No puedes hacer una entrega a ti mismo", "AUTOTRANSFERENCIA");
      }

      const cantidadTrigo = Math.min(
        numeroNoNegativo(trigo, 0),
        emisor.trigo
      );

      const cantidadHierro = Math.min(
        numeroNoNegativo(hierro, 0),
        emisor.hierro
      );

      if (cantidadTrigo === 0 && cantidadHierro === 0) {
        return respuestaError(
          socket,
          "La entrega debe contener trigo o hierro",
          "ENTREGA_VACIA"
        );
      }

      emisor.trigo -= cantidadTrigo;
      emisor.hierro -= cantidadHierro;
      receptor.trigo += cantidadTrigo;
      receptor.hierro += cantidadHierro;
      emisor.entregas += 1;
      if (data.config.maxEntregas >= 0 && emisor.entregas >= data.config.maxEntregas) {
        emisor.entregasMaximoAlcanzado = true;
      }

      data.historial.push({
        id: generarId(),
        sesion: data.numeroSesion,
        de,
        deNombreVisible: emisor.nombreVisible || de,
        para: receptorNombre,
        paraNombreVisible: receptor.nombreVisible || receptorNombre,
        trigo: cantidadTrigo,
        hierro: cantidadHierro,
        timestamp: ahora(),
      });
      data.updatedAt = ahora();

      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo realizar la entrega", "ERROR_ENTREGA");
    }
  });

  // ---------------------------------------------------------------------------
  // CAMBIO DE FASE: CERRAR ENTREGAS -> PRODUCCIÓN
  // ---------------------------------------------------------------------------

  socket.on("toggleEntregas", async (sala) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      if (data.fase !== "entregas") {
        return respuestaError(
          socket,
          "La sala no está en fase de entregas",
          "FASE_INCORRECTA"
        );
      }

      // Capturamos los recursos disponibles al terminar las entregas y
      // registramos exactamente cuándo se cierra una fase y se abre la siguiente.
      const cierreEntregasAt = ahora();
      for (const jugador of Object.values(data.jugadores)) {
        jugador.trigoInsumo = jugador.trigo;
        jugador.hierroInsumo = jugador.hierro;
      }
      data.sesionActualTiempos = data.sesionActualTiempos || {};
      data.sesionActualTiempos.entregasCerradasAt = cierreEntregasAt;
      data.sesionActualTiempos.produccionAbiertaAt = cierreEntregasAt;
      data.sesionActualRecursosDespuesEntregas = {};
      for (const [nombre, jugador] of Object.entries(data.jugadores)) {
        data.sesionActualRecursosDespuesEntregas[nombre] = {
          nombreVisible: jugador.nombreVisible || nombre,
          trigo: jugador.trigo,
          hierro: jugador.hierro,
        };
      }

      data.fase = "produccion";
      registrarAuditoria(data, "fase", {
        accion: "Cambio de fase",
        deFase: "entregas",
        aFase: "produccion",
      });
      data.updatedAt = cierreEntregasAt;

      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo cambiar de fase", "ERROR_FASE");
    }
  });

  // ---------------------------------------------------------------------------
  // ELEGIR PROCESO
  // ---------------------------------------------------------------------------

  socket.on("elegirProceso", async ({ sala, proceso } = {}) => {
    try {
      const contexto = exigirJugador(socket, sala);
      if (!contexto) return;

      const { data, jugador } = contexto;

      if (data.fase !== "produccion") {
        return respuestaError(
          socket,
          "La producción está cerrada",
          "FASE_INCORRECTA"
        );
      }

      const procesoN = Number(proceso);

      if (![1, 2, 3].includes(procesoN)) {
        return respuestaError(socket, "Proceso no válido", "PROCESO_INVALIDO");
      }

      if (jugador.proceso !== null) {
        return respuestaError(
          socket,
          "El proceso ya ha sido elegido y no puede cambiarse",
          "PROCESO_YA_ELEGIDO"
        );
      }

      jugador.proceso = procesoN;
      jugador.produccionAt = ahora();
      data.updatedAt = jugador.produccionAt;

      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo elegir el proceso", "ERROR_PROCESO");
    }
  });

  // ---------------------------------------------------------------------------
  // CERRAR PRODUCCIÓN -> APLICAR PRODUCCIÓN -> NUEVA SESIÓN
  // ---------------------------------------------------------------------------

  socket.on("toggleProduccion", async (sala) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      if (data.fase !== "produccion") {
        return respuestaError(
          socket,
          "La sala no está en fase de producción",
          "FASE_INCORRECTA"
        );
      }

      const finalizadaAt = ahora();
      for (const jugador of Object.values(data.jugadores)) {
        // Si no eligió, la regla de OIKOS establece que utiliza el proceso 3.
        const proceso = jugador.proceso ?? 3;
        // Si el jugador no eligió explícitamente un proceso, la producción se
        // ejecuta al cerrar la fase y usamos ese instante como referencia.
        if (!jugador.produccionAt) jugador.produccionAt = finalizadaAt;

        if (proceso === 1) {
          const factor = Math.min(
            jugador.trigoInsumo / 280,
            jugador.hierroInsumo / 12
          );

          jugador.trigoProd = 575 * Math.max(0, factor);
          jugador.hierroProd = 0;
        } else if (proceso === 2) {
          const factor = Math.min(
            jugador.trigoInsumo / 120,
            jugador.hierroInsumo / 8
          );

          jugador.trigoProd = 0;
          jugador.hierroProd = 20 * Math.max(0, factor);
        } else {
          jugador.trigoProd = jugador.trigoInsumo / 2;
          jugador.hierroProd = jugador.hierroInsumo / 2;
        }

        // Los insumos se consumen completamente.
        jugador.trigo = jugador.trigoProd;
        jugador.hierro = jugador.hierroProd;
        jugador.entregas = 0;
      }

      // Guardamos una copia completa de la sesión que acaba de terminar.
      const produccionSesion = {};
      for (const [nombre, jugador] of Object.entries(data.jugadores)) {
        produccionSesion[nombre] = {
          nombreVisible: jugador.nombreVisible || nombre,
          trigoInicioSesion: data.sesionActualRecursosIniciales?.[nombre]?.trigo ?? null,
          hierroInicioSesion: data.sesionActualRecursosIniciales?.[nombre]?.hierro ?? null,
          trigoInicial: data.sesionActualRecursosIniciales?.[nombre]?.trigo ?? null,
          hierroInicial: data.sesionActualRecursosIniciales?.[nombre]?.hierro ?? null,
          trigoDespuesEntregas: jugador.trigoInsumo,
          hierroDespuesEntregas: jugador.hierroInsumo,
          proceso: jugador.proceso ?? 3,
          produccionAt: jugador.produccionAt || null,
          trigoProducido: jugador.trigoProd,
          hierroProducido: jugador.hierroProd,
          trigoFinal: jugador.trigo,
          hierroFinal: jugador.hierro,
        };
      }

      // Crear el registro histórico ANTES de modificar la sesión actual.
      // Se guarda una copia independiente para que nunca dependa del estado
      // que tengan los jugadores después de comenzar la siguiente sesión.
      data.sesionActualTiempos = data.sesionActualTiempos || {};
      data.sesionActualTiempos.produccionCerradaAt = finalizadaAt;
      registrarAuditoria(data, "fase", {
        accion: "Cambio de fase",
        deFase: "produccion",
        aFase: "pausa",
      });
      const sesionTerminada = {
        numeroSesion: data.numeroSesion,
        iniciadaAt: data.sesionActualIniciadaAt || data.createdAt,
        entregasAbiertasAt: data.sesionActualTiempos.entregasAbiertasAt || data.sesionActualIniciadaAt || data.createdAt,
        entregasCerradasAt: data.sesionActualTiempos.entregasCerradasAt || null,
        produccionAbiertaAt: data.sesionActualTiempos.produccionAbiertaAt || null,
        produccionCerradaAt: finalizadaAt,
        finalizadaAt,
        tiempos: copiar(data.sesionActualTiempos),
        recursosIniciales: copiar(data.sesionActualRecursosIniciales || {}),
        recursosDespuesEntregas: copiar(data.sesionActualRecursosDespuesEntregas || {}),
        entregas: (data.historial || []).map(e => ({ ...e })),
        produccion: copiar(produccionSesion),
        auditoria: copiar((data.historialAuditoria || []).filter(e => Number(e.sesion) === Number(data.numeroSesion))),
      };

      // Añadimos al registro de la sesión únicamente la auditoría administrativa.
      sesionTerminada.auditoria = copiar((data.historialAuditoria || []).filter(e => Number(e.sesion) === Number(data.numeroSesion)));

      data.historialSesiones = Array.isArray(data.historialSesiones)
        ? data.historialSesiones
        : [];
      data.historialSesiones.push(sesionTerminada);

      // Persistimos el historial en su propio archivo y en el estado general
      // ANTES de vaciar la sesión actual. Así el historial no depende del
      // navegador ni de una actualización de Socket.IO.
      data.updatedAt = ahora();
      await guardarHistorialPersistente(sala);
      await encolarGuardado();
      await guardarHistorial(sala);

      // Cerramos la producción, pero dejamos una pausa explícita antes de
      // permitir la siguiente sesión. Durante esta fase no hay entregas ni
      // producción posibles.
      data.fase = "pausa";
      data.updatedAt = ahora();

      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo cerrar la producción", "ERROR_PRODUCCION");
    }
  });

  // ---------------------------------------------------------------------------
  // COMPATIBILIDAD: toggleProduccionAbierta
  //
  // Ya no se permite cambiar directamente el booleano porque rompería la
  // máquina de estados. Se conserva el evento para que un cliente antiguo
  // reciba un error claro en lugar de producir un estado incoherente.
  // ---------------------------------------------------------------------------

  socket.on("toggleProduccionAbierta", (sala) => {
    respuestaError(
      socket,
      "Este evento ha quedado obsoleto. Usa toggleEntregas o toggleProduccion.",
      "EVENTO_OBSOLETO"
    );
  });

  // ---------------------------------------------------------------------------
  // NUEVA SESIÓN
  //
  // Se conserva por compatibilidad, pero ahora significa reiniciar la partida
  // en una sesión nueva desde los recursos actuales.
  // ---------------------------------------------------------------------------

  socket.on("nuevaSesion", async (sala) => {
    try {
      const data = exigirAdmin(socket, sala);
      if (!data) return;

      if (data.fase !== "pausa") {
        return respuestaError(
          socket,
          "La sala no está en pausa entre sesiones",
          "FASE_INCORRECTA"
        );
      }

      for (const jugador of Object.values(data.jugadores)) {
        jugador.trigoInsumo = jugador.trigo;
        jugador.hierroInsumo = jugador.hierro;
        jugador.trigoProd = 0;
        jugador.hierroProd = 0;
        jugador.proceso = null;
        jugador.produccionAt = null;
        jugador.entregas = 0;
        jugador.entregasMaximoAlcanzado = false;
      }

      data.fase = "entregas";
      const inicioSesionAt = ahora();
      data.sesionActualIniciadaAt = inicioSesionAt;
      data.sesionActualTiempos = {
        sesionAbiertaAt: inicioSesionAt,
        entregasAbiertasAt: inicioSesionAt,
      };
      data.sesionActualRecursosIniciales = {};
      for (const [nombre, jugador] of Object.entries(data.jugadores)) {
        data.sesionActualRecursosIniciales[nombre] = {
          nombreVisible: jugador.nombreVisible || nombre,
          trigo: jugador.trigo,
          hierro: jugador.hierro,
        };
      }
      data.sesionActualRecursosDespuesEntregas = {};
      const esPrimeraSesion = data.numeroSesion === 1 &&
        (!Array.isArray(data.historialSesiones) || data.historialSesiones.length === 0) &&
        (!Array.isArray(data.historial) || data.historial.length === 0);
      if (!esPrimeraSesion) data.numeroSesion += 1;
      registrarAuditoria(data, "fase", {
        accion: "Cambio de fase",
        deFase: "pausa",
        aFase: "entregas",
      });
      // La marca de tiempo y los recursos corresponden a la sesión que acaba de abrirse.
      data.historial = [];
      data.updatedAt = ahora();

      await encolarGuardado();
      emitirEstado(sala);
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo iniciar una nueva sesión", "ERROR_NUEVA_SESION");
    }
  });


  // ---------------------------------------------------------------------------
  // CONSULTAR HISTORIAL
  // ---------------------------------------------------------------------------
  // Permite a las consolas solicitar el historial explícitamente. Esto evita
  // depender de una actualización anterior del estado del navegador.
  socket.on("solicitarHistorial", async (sala) => {
    try {
      const data = obtenerSalaDesdeSocket(socket, sala);
      if (!data) return;
      socket.emit("historialSesiones", historialSesionesPublico(data, socket));
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo cargar el historial", "ERROR_HISTORIAL");
    }
  });

  socket.on("solicitarHistorialEdicionesJugadores", async (sala) => {
    try {
      const data = obtenerSalaDesdeSocket(socket, sala);
      if (!data) return;
      socket.emit("historialEdicionesJugadores", historialEdicionesJugadoresPublico(data, socket));
    } catch (err) {
      console.error(err);
      respuestaError(socket, "No se pudo cargar el historial de ediciones", "ERROR_HISTORIAL_EDICIONES");
    }
  });

  // ---------------------------------------------------------------------------
  // DESCONECTAR
  // ---------------------------------------------------------------------------

  socket.on("disconnect", () => {
    console.log("Usuario desconectado:", socket.id);

    for (const nombreSala of Object.keys(salas)) {
      const data = salas[nombreSala];

      if (data.adminId === socket.id) {
        // No destruimos la identidad de la partida.
        // Otro login del administrador podrá recuperar el control.
        data.adminId = null;
        data.updatedAt = ahora();
        encolarGuardado();
      }
    }
  });
});

// -----------------------------------------------------------------------------
// ARRANQUE
// -----------------------------------------------------------------------------

cargarEstado()
  .then(() => migrarArchivosHistoricosGenericos())
  .then(() => recuperarHistorialesDesdeArchivos())
  .catch((err) => console.error("Error inicializando estado:", err))
  .finally(() => {
    server.listen(PORT, () => {
      console.log(`Servidor iniciado en http://localhost:${PORT}`);
    });
  });
