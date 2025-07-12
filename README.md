# Cryptography CLI - Python Version

Implementación en Python del proyecto de criptografía CLI basado en el curso de Platzi.

## 🔗 Repositorio Original

Este proyecto es una **adaptación en Python** del curso de criptografía de Platzi:
- 📚 **Repositorio original**: [platzi/curso-criptografia](https://github.com/platzi/curso-criptografia)
- 💻 **Tecnología original**: TypeScript/Node.js
- 🐍 **Esta versión**: Python con `uv` como gestor de dependencias

### ¿Por qué esta versión?
- Implementación en Python para aprender el ecosistema Python moderno
- Uso de `uv` como gestor de dependencias de alta velocidad
- Mejoras en validación de algoritmos y manejo de errores
- Estructura adaptada a las mejores prácticas de Python

## Instalación

### Con uv (recomendado)
```bash
# Instalar uv si no lo tienes
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sincronizar dependencias
uv sync
```

### Con pip (alternativo)
```bash
pip install cryptography>=41.0.0 click>=8.1.0
```

## Uso General

Los comandos pueden ejecutarse de dos maneras:

**Con uv (recomendado):**
```bash
uv run python main.py <comando> [opciones]
```

**Con pip:**
```bash
python -m src.main <comando> [opciones]
```

## Comandos Disponibles

### Generar números aleatorios
```bash
# Generar bytes aleatorios
uv run python main.py prng --type bytes --size 16 --encoding hex

# Generar número entero aleatorio
uv run python main.py prng --type int --min 1 --max 100

# Generar UUID
uv run python main.py prng --type uuid
```

### Cifrado y descifrado
```bash
# Cifrar un archivo
uv run python main.py cipher --password mypassword --salt mysalt --input file.txt --output file.enc

# Descifrar un archivo
uv run python main.py decipher --password mypassword --salt mysalt --input file.enc --output file_decrypted.txt
```

### Derivación de claves con scrypt
```bash
uv run python main.py scrypt --password mypassword --salt mysalt --size 32 --encoding hex
```

### Hash de archivos
```bash
# Hash básico con SHA256 (por defecto)
uv run python main.py hash --input file.txt

# Usar un algoritmo específico
uv run python main.py hash --algorithm sha512 --input file.txt --encoding hex

# Ver algoritmos comunes con descripciones
uv run python main.py hash --show-common

# Listar todos los algoritmos soportados
uv run python main.py hash --list-algorithms
```

**Algoritmos más comunes:**
- **sha256**: SHA-256 (256-bit) - Más utilizado, buena seguridad
- **sha512**: SHA-512 (512-bit) - Muy seguro, más lento que SHA-256
- **sha3_256**: SHA3-256 (256-bit) - Estándar más reciente, muy seguro
- **blake2b**: BLAKE2b - Rápido y seguro, buena alternativa a SHA-2

### HMAC (Autenticación de mensajes)
```bash
# HMAC básico con SHA256
uv run python main.py hmac --algorithm sha256 --key mykey --input file.txt --encoding hex

# Para máxima seguridad (recomendado para datos críticos)
uv run python main.py hmac --algorithm sha512 --key secure-key --input document.pdf --encoding base64

# Para compatibilidad con sistemas legacy
uv run python main.py hmac --algorithm sha1 --key legacy-key --input data.txt --encoding hex
```

**Características HMAC:**
- Reproducible: La misma clave + archivo = mismo HMAC
- Resistente a modificaciones: Cualquier cambio modifica completamente el HMAC
- Seguro: Requiere conocer la clave secreta para generar HMACs válidos

### Generación de pares de claves
```bash
uv run python main.py keypair --type rsa --passphrase mypassphrase --out-dir ./keys --modulus-length 2048
```

### Firma digital
```bash
uv run python main.py sign --algorithm RSA-SHA256 --input file.txt --private-key ./keys/private.pem --passphrase mypassphrase --encoding hex
```

### Verificación de firmas
```bash
uv run python main.py verify --algorithm RSA-SHA256 --input file.txt --public-key ./keys/public.pem --signature <signature_hex> --signature-encoding hex
```

### Diffie-Hellman (intercambio de claves)
```bash
uv run python main.py diffie-hellman --encoding hex
```

## 📝 Casos de Uso Prácticos

### Hash de Archivos

**Verificación de Integridad:**
```bash
# Generar hash de un archivo importante
uv run python main.py hash -a sha256 -i documento_importante.pdf
# Guardar el resultado para verificación posterior
```

**Comparación de Archivos:**
```bash
# Comparar dos archivos mediante sus hashes
uv run python main.py hash -a sha256 -i archivo1.txt
uv run python main.py hash -a sha256 -i archivo2.txt
# Si los hashes son idénticos, los archivos son idénticos
```

**Elección de Algoritmo:**
```bash
# Para velocidad (archivos grandes)
uv run python main.py hash -a blake2b -i archivo_grande.zip

# Para máxima seguridad (documentos críticos)
uv run python main.py hash -a sha3_512 -i contrato_importante.pdf

# Para compatibilidad legacy
uv run python main.py hash -a sha256 -i datos_legacy.txt
```

### HMAC para Autenticación

**Flujo de Verificación de Integridad:**
```bash
# 1. Emisor genera HMAC del archivo
uv run python main.py hmac -a sha256 -k "shared-secret-2024" -i contract.pdf --enc hex

# 2. Receptor verifica integridad generando el mismo HMAC
uv run python main.py hmac -a sha256 -k "shared-secret-2024" -i received_contract.pdf --enc hex
# Si el output coincide, el archivo es íntegro y auténtico
```

## Notas Importantes

- **uv es la forma recomendada** de gestionar este proyecto ya que maneja automáticamente el entorno virtual y las dependencias
- Con `uv run`, no necesitas activar manualmente un entorno virtual
- Los archivos de claves se generan en el directorio `.secrets` por defecto
- Se recomienda usar contraseñas seguras para proteger las claves privadas

## 🔧 Funcionalidades Implementadas

Todas las funcionalidades del proyecto original han sido portadas y mejoradas:

- ✅ **PRNG**: Generación de números aleatorios criptográficamente seguros
- ✅ **Cifrado simétrico**: AES con derivación de claves mediante scrypt
- ✅ **Hash mejorado**: 
  - Validación automática de algoritmos soportados
  - Soporte para 19+ algoritmos (SHA-2, SHA-3, BLAKE2, etc.)
  - Opciones para listar algoritmos y ver descripciones
  - Manejo robusto de errores
- ✅ **HMAC**: Autenticación de mensajes con múltiples algoritmos
- ✅ **Scrypt**: Derivación de claves robusta contra ataques
- ✅ **RSA**: Generación de pares de claves asimétricas
- ✅ **Firma digital**: RSA-SHA256 para autenticación de documentos
- ✅ **Verificación**: Validación de firmas digitales
- ✅ **Diffie-Hellman**: Intercambio seguro de claves

### ⭐ Mejoras Específicas sobre el Original

1. **Validación de Algoritmos**: Verificación automática de compatibilidad con `hashlib`
2. **Opciones de Descubrimiento**: `--list-algorithms` y `--show-common`
3. **Soporte Amplio**: SHA-2, SHA-3, BLAKE2 y más familias de algoritmos
4. **Manejo de Errores**: Validación robusta con mensajes informativos

## Comandos Útiles de uv

```bash
# Ver información del proyecto
uv show

# Actualizar dependencias
uv sync --upgrade

# Añadir nueva dependencia
uv add <package-name>

# Ejecutar cualquier comando en el entorno
uv run <command>
```

## 📊 Comparación con el Original

| Aspecto | Original (TypeScript) | Esta versión (Python) |
|---------|----------------------|----------------------|
| **Lenguaje** | TypeScript/Node.js | Python 3.13+ |
| **Gestor de dependencias** | npm/yarn | uv |
| **Estructura** | Módulos ES6 | Módulos Python |
| **CLI Framework** | Commander.js | Click |
| **Crypto Library** | Node.js crypto | Python cryptography |
| **Configuración** | package.json | pyproject.toml |

## 🎓 Créditos

- **Curso original**: [Curso de Criptografía](https://platzi.com/cursos/criptografia/) - Platzi
- **Repositorio original**: [platzi/curso-criptografia](https://github.com/platzi/curso-criptografia)
- **Adaptación a Python**: Implementación propia basada en el curso original
