# NIDS-ML: detector de intrusiones de red con machine learning

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![FastAPI](https://img.shields.io/badge/Web-FastAPI-009688)
![LightGBM](https://img.shields.io/badge/ML-LightGBM%20%2F%20XGBoost-red)
![Estado](https://img.shields.io/badge/estado-en%20desarrollo-orange)

Sistema de detección de intrusiones de red (NIDS) que clasifica flujos de tráfico como
normales o como ataques (escaneos de puertos, fuerza bruta, DoS/DDoS, botnets, ataques web…).
Se evalúa **con honestidad**: frente a reglas clásicas, contando las falsas alarmas y probando
ataques que el modelo **no vio nunca** al entrenar. Además, explica cada alerta con SHAP.

Un panel web reproduce un día de tráfico real acelerado y va marcando las alertas en directo.
Para cada alerta enseña qué la ha provocado y si una regla clásica la habría detectado.

> Proyecto en desarrollo. Las cifras de la sección de resultados se rellenan a medida que se
> obtienen; ninguna está estimada a ojo.

---

## Qué hace

- **Detecta ataques conocidos** en flujos de red con un modelo de gradient boosting (LightGBM
  o XGBoost) entrenado con CIC-IDS2017.
- **Mide cuánto aguanta ante ataques nuevos.** Se entrena sin una familia de ataques entera y
  se comprueba si la detecta igualmente, con el clasificador y con un detector de anomalías
  entrenado solo con tráfico normal.
- **Se compara con referencias**: reglas de umbral como las de un IDS clásico, un modelo lineal
  y no hacer nada.
- **Explica cada alerta** con SHAP, en lenguaje claro: por ejemplo, «contacta con muchos puertos
  distintos en muy poco tiempo».
- **Panel de reproducción**: el tráfico del día de test pasa en el tiempo, las alertas aparecen
  según llegan y se puede pulsar cualquiera para ver su explicación.

## Por qué esto no es tan fácil como parece

Es habitual ver detectores de intrusiones con un 99 % de *accuracy* en estos datasets. Casi
siempre ese número engaña:

- **El tráfico normal es la inmensa mayoría.** Un modelo que dijera siempre «normal» ya tendría
  una *accuracy* altísima. Por eso aquí se miden el recall de cada tipo de ataque, la precisión
  y, sobre todo, las **falsas alarmas por hora**: es lo que decide si un analista puede usar el
  sistema o lo apaga.
- **Repartir los flujos al azar entre entrenamiento y test hace trampa.** Los flujos de un mismo
  ataque se parecen muchísimo entre sí, así que el modelo «reconoce» el ataque en vez de
  aprender a detectarlo. Aquí el reparto es **temporal**: se entrena con lo que pasó antes y se
  prueba con lo que pasó después.
- **Algunas columnas delatan la respuesta** (IPs, identificadores de flujo, marcas de tiempo).
  Se eliminan antes de entrenar.
- **El CIC-IDS2017 original tiene errores conocidos** de etiquetado y de extracción de flujos.
  Se usa la versión corregida por Engelen et al. (2021).

## Datos

| Dataset | Uso | Notas |
|---|---|---|
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (versión corregida de Engelen et al., 2021) | Entrenamiento y test principal | 5 días de tráfico (lunes a viernes) con ataques reales en una red de laboratorio. El lunes solo hay tráfico normal. |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Prueba en otra red (opcional) | Otra red y otras herramientas: mide si el modelo generaliza fuera del laboratorio en el que se entrenó. |

Los datos no se suben al repositorio: `make data` los descarga y los prepara en `data/`.

## Cómo se evalúa

| Protocolo | Pregunta que responde | Cómo |
|---|---|---|
| **Ataques conocidos** | ¿Detecta los tipos de ataque que ha visto? | Reparto temporal dentro de cada día: el principio para entrenar y el final para test. |
| **Ataques nuevos** | ¿Detecta un tipo de ataque que no ha visto nunca? | Se deja fuera una familia de ataques entera al entrenar (*leave-one-attack-out*). |
| **Otra red** *(opcional)* | ¿Funciona fuera del laboratorio en el que se entrenó? | Se entrena con CIC-IDS2017 y se prueba con UNSW-NB15, usando solo las variables comunes. |

**Métricas:** recall y precisión por tipo de ataque, PR-AUC, tasa de falsos positivos y falsas
alarmas por hora de tráfico normal. La *accuracy* aparece solo junto a la de «decir siempre
normal», para que se vea lo poco que significa.

**Referencias:** reglas de umbral al estilo de un IDS clásico (p. ej., muchos puertos de destino
distintos en poco tiempo → escaneo), regresión logística y «siempre normal».

## Resultados

[PENDIENTE: tabla por protocolo con el modelo frente a las reglas y la regresión logística,
falsas alarmas por hora y recall por familia de ataque. Si el modelo no mejora a las reglas en
algún caso, se dice tal cual.]

## Arranque rápido

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

make data        # descarga y limpia CIC-IDS2017 (varios GB, solo la primera vez)
make train       # entrena las referencias y el modelo
make evaluate    # ejecuta los tres protocolos y guarda los informes en reports/
make web         # panel en http://127.0.0.1:8000
make test        # tests
```

## Arquitectura

```
config/         config.yaml: rutas, semillas, reparto temporal, umbrales de las reglas
src/nids/
  data/         descarga, limpieza y unificación de etiquetas
  features/     selección de variables y eliminación de las que delatan la respuesta
  models/       referencias (reglas, lineal), modelo principal, detector de anomalías
  evaluation/   protocolos, métricas y falsas alarmas por hora
  explain/      SHAP y traducción de cada alerta a lenguaje claro
  replay/       reproducción temporal del día de test
  web/          FastAPI + HTMX + SSE (panel en directo)
tests/          pytest con datos sintéticos pequeños
reports/        métricas y gráficos generados (se versionan los resúmenes)
```

## Limitaciones conocidas

- Los datasets son de laboratorio. Un buen resultado aquí no garantiza el mismo resultado en
  una red real, y el protocolo «otra red» sirve precisamente para medirlo.
- El modelo trabaja con flujos ya extraídos, no con paquetes en directo. Analizar capturas
  `.pcap` propias está en la hoja de ruta.
- Es un proyecto de aprendizaje e investigación, no un producto de seguridad.

## Uso responsable

Este proyecto solo analiza datasets públicos y tráfico propio. Si en algún momento se prueba
con tráfico generado (escaneos, fuerza bruta…), se hace contra máquinas propias en un
laboratorio aislado y nunca contra sistemas de terceros sin autorización.

## Referencias

- Sharafaldin, Lashkari y Ghorbani (2018). *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization*. ICISSP.
- Engelen, Rimmer y Joosen (2021). *Troubleshooting an Intrusion Detection Dataset: the
  CICIDS2017 Case Study*. IEEE Security and Privacy Workshops.
- Moustafa y Slay (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection
  systems*. MilCIS.

## Autor

**Joaquín José Cruz Lorenzo**
GitHub: [@juakincruzz](https://github.com/juakincruzz) · Web: [joaquinjcl.dev](https://joaquinjcl.dev)
