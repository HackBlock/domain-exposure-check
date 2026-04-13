# Domain Exposure Check

Analiza en segundos la exposición pública de cualquier dominio ante ataques de phishing, spoofing y typosquatting.

Esta herramienta de OSINT pasivo está diseñada para equipos de seguridad, consultores y CTOs que necesitan auditar qué información tienen los atacantes a su alcance antes de lanzar una campaña de ingeniería social o una auditoría de seguridad.

# Vista Previa (Terminal)

<img width="856" height="501" alt="image" src="https://github.com/user-attachments/assets/60bc95d6-e1c5-47bb-9d53-ee3d1fc4d145" />


## Detalle de la Herramienta

domain-exposure-check es un escáner de línea de comandos (CLI) escrito en Python que automatiza la recolección de datos críticos de infraestructura de correo y exposición de identidad. A diferencia de otros escáneres, esta herramienta no solo verifica la existencia de registros, sino que evalúa la fortaleza de las políticas configuradas y calcula un Risk Score basado en el impacto real de cada hallazgo.

### Capacidades principales

1.  **Auditoría de Email Authentication (SPF, DMARC, DKIM):**
    * Verifica la configuración de los protocolos de seguridad de correo.
    * Extrae y muestra el contenido raw de los registros para validación técnica inmediata.
    * Detecta errores comunes como registros SPF múltiples o políticas DMARC en modo "none" que no ofrecen protección real.
2.  **Identificación de Infraestructura:**
    * Analiza los registros MX para determinar el proveedor de correo (Google Workspace, Microsoft 365, etc.), lo que permite a un atacante perfilar sus plantillas de phishing.
3.  **Detección Concurrente de Typosquatting:**
    * Genera automáticamente decenas de variantes del dominio (omisiones, duplicaciones, sustituciones de teclado).
    * Utiliza hilos (ThreadPoolExecutor) para resolver DNS de forma masiva y rápida, identificando dominios similares que ya están registrados y activos.
4.  **Exposición de Credenciales e Identidad (OSINT):**
    * Integración con Hunter.io para listar correos electrónicos indexados públicamente.
    * Cálculo de penalizaciones en el score según la cantidad de correos expuestos.

---

## Qué analiza

| Categoría | Descripción |
| :--- | :--- |
| SPF | Analiza registros v=spf1. Detecta configuraciones débiles (~all, ?all) o ausentes. |
| DMARC | Evalúa la política (p=none/quarantine/reject) y la presencia de reportes (rua). |
| DKIM | Prueba selectores comunes (google, default, mail...) para confirmar firma digital. |
| MX / Proveedor | Identifica el stack de correo y posibles gateways de seguridad (Mimecast, etc). |
| Typosquatting | Genera y resuelve variantes del dominio para detectar registros maliciosos. |
| Emails Expuestos | Consulta Hunter.io para mostrar la superficie de ataque para Spear-phishing. |

El resultado se consolida en un Risk Score (0-100) con niveles: BAJO, MEDIO, ALTO o CRÍTICO.

---

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/HackBlock/domain-exposure-check.git
cd domain-exposure-check

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # En Linux/macOS
# En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Configurar API Key (opcional)
# Agrega esta línea a tu ~/.bashrc o ~/.zshrc:
export HUNTER_API_KEY="tu-api-key-aqui"
```

### Uso desde cualquier ruta (Alias)

Para ejecutar la herramienta desde cualquier directorio sin activar el entorno virtual manualmente, agrega un alias a tu `~/.bashrc` o `~/.zshrc`:

```bash
alias domain-check="/home/<tu-usuario>/domain-exposure-check/venv/bin/python /home/<tu-usuario>/domain-exposure-check/domain-exposure-check.py"
```

Luego recarga tu configuración:
```bash
source ~/.bashrc  # o source ~/.zshrc
```

Ahora puedes ejecutar desde cualquier ruta:
```bash
domain-check empresa.com
```
Requisito: Python 3.9+ y la librería dnspython.
# Uso
Análisis básico

```bash
python domain-exposure-check.py empresa.com
```

Exportación para integraciones (JSON)
```bash
python domain-exposure-check.py empresa.com --json
```

Máximo detalle (API Keys)
Puedes configurar la clave como variable de entorno (HUNTER_API_KEY) o pasarla como parámetro:
```bash
python domain-exposure-check.py empresa.com --hunter-key TU_KEY_AQUÍ
```
# Casos de uso
**Auditoría Inicial:** Primera toma de contacto técnica en un engagement de concienciación.

**Red Team Recon:** Recolección de información sin interactuar directamente con la infraestructura del objetivo.

# Ética y Limitaciones
Esta herramienta realiza únicamente consultas pasivas a DNS y APIs públicas. No envía tráfico malicioso ni intenta acceder a servicios privados.

El check de typosquatting realiza resoluciones DNS, lo cual deja trazas estándar en los logs de los resolvers.

Uso responsable: Utiliza esta herramienta solo en dominios sobre los que tienes autorización o con fines de investigación legítima.

# Por HackBlock
Expertos en simulación de phishing y seguridad humana.
Sitio web: https://hack-block.com

*Licencia: MIT.*
