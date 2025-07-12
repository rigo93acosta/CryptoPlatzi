# Cryptography CLI - Python Version

Este es la versión en Python del proyecto de criptografía CLI.

## 🔗 Repositorio Original

Este proyecto es un **clon en Python** del curso de criptografía de Platzi:
- 📚 **Repositorio original**: [platzi/curso-criptografia](https://github.com/platzi/curso-criptografia)
- 💻 **Tecnología original**: TypeScript/Node.js
- 🐍 **Esta versión**: Python con `uv` como gestor de dependencias

### ¿Por qué esta versión?
- Implementación en Python para aprender el ecosistema Python
- Uso de `uv` como gestor moderno de dependencias
- Mantiene la misma funcionalidad del proyecto original
- Estructura de código adaptada a las mejores prácticas de Python

## Instalación

### Con uv (recomendado)
```bash
# Instalar uv si no lo tienes
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sincronizar dependencias
uv sync

# O si quieres instalar en un entorno específico
uv venv
uv pip sync uv.lock
```

### Con pip (alternativo)
```bash
pip install cryptography>=41.0.0 click>=8.1.0
```

## Uso

### Con uv (recomendado)
Todos los comandos deben ejecutarse con `uv run` para usar el entorno virtual gestionado por uv:

### Con pip (alternativo)
Si instalaste con pip, usa `python -m` directamente.

### Generar números aleatorios
#### Con uv:
```bash
uv run python main.py prng --type bytes --size 16 --encoding hex
uv run python main.py prng --type int --min 1 --max 100
uv run python main.py prng --type uuid
```

#### Con pip:
```bash
python -m src.main prng --type bytes --size 16 --encoding hex
python -m src.main prng --type int --min 1 --max 100
python -m src.main prng --type uuid
```

### Cifrado y descifrado
#### Con uv:
```bash
# Cifrar un archivo
uv run python main.py cipher --password mypassword --salt mysalt --input file.txt --output file.enc

# Descifrar un archivo
uv run python main.py decipher --password mypassword --salt mysalt --input file.enc --output file_decrypted.txt
```

#### Con pip:
```bash
# Cifrar un archivo
python -m src.main cipher --password mypassword --salt mysalt --input file.txt --output file.enc

# Descifrar un archivo
python -m src.main decipher --password mypassword --salt mysalt --input file.enc --output file_decrypted.txt
```

### Derivación de claves con scrypt
#### Con uv:
```bash
uv run python main.py scrypt --password mypassword --salt mysalt --size 32 --encoding hex
```

#### Con pip:
```bash
python -m src.main scrypt --password mypassword --salt mysalt --size 32 --encoding hex
```

### Hash de archivos
#### Con uv:
```bash
# Hash básico con SHA256 (por defecto)
uv run python main.py hash --input file.txt

# Usar un algoritmo específico
uv run python main.py hash --algorithm sha512 --input file.txt --encoding hex

# Cambiar formato de salida
uv run python main.py hash --algorithm blake2b --input file.txt --encoding base64

# Ver algoritmos comunes con descripciones
uv run python main.py hash --show-common

# Listar todos los algoritmos soportados
uv run python main.py hash --list-algorithms
```

#### Con pip:
```bash
# Hash básico con SHA256 (por defecto)
python -m src.main hash --input file.txt

# Usar un algoritmo específico
python -m src.main hash --algorithm sha512 --input file.txt --encoding hex

# Cambiar formato de salida
python -m src.main hash --algorithm blake2b --input file.txt --encoding base64

# Ver algoritmos comunes con descripciones
python -m src.main hash --show-common

# Listar todos los algoritmos soportados
python -m src.main hash --list-algorithms
```

#### Algoritmos soportados:
La implementación valida automáticamente que el algoritmo especificado sea compatible con `hashlib`. Los algoritmos más comunes incluyen:

- **sha256**: SHA-256 (256-bit) - Más utilizado, buena seguridad
- **sha512**: SHA-512 (512-bit) - Muy seguro, más lento que SHA-256
- **sha3_256**: SHA3-256 (256-bit) - Estándar más reciente, muy seguro
- **sha3_512**: SHA3-512 (512-bit) - Estándar más reciente, máxima seguridad
- **blake2b**: BLAKE2b - Rápido y seguro, buena alternativa a SHA-2
- **blake2s**: BLAKE2s - Optimizado para plataformas de 8-32 bits
- **md5**: MD5 (128-bit) - Rápido pero criptográficamente roto (no recomendado)
- **sha1**: SHA-1 (160-bit) - Obsoleto, usar SHA-2 en su lugar

#### Ejemplos de uso:
```bash
# Ejemplo 1: Hash con diferentes algoritmos
uv run python main.py hash -a sha256 -i test_file.txt
# Output: 4d8f630afa4c35ecb8f4c52ebc81cb595c3588fce5831ea0b1a70766618b5796

uv run python main.py hash -a sha512 -i test_file.txt
# Output: fc04da43faf24572d3e0aba41d3e325971a9e85c9c3cd609e6b8a98cdd5cce321466e891d38fa3d740203ad58431da6ca7a47ff85abf8161ca8e56e3a04ae82a

# Ejemplo 2: Hash con diferentes codificaciones
uv run python main.py hash -a blake2b -i test_file.txt --enc base64
# Output: madJPJ+u0fimPkIjZlUMX4JPieqWkGi1tBGv7Qqnm/xyZBWnsurYvVpPFfgg8Dnyh0c3wIbAEHsG8z9RlF3QUw==

# Ejemplo 3: Validación de algoritmos
uv run python main.py hash -a algoritmo_inexistente -i test_file.txt
# Output: Error: Algorithm 'algoritmo_inexistente' is not supported. Supported algorithms: blake2b, blake2s, md5, md5-sha1, ripemd160, sha1, sha224, sha256, sha384, sha3_224, sha3_256, sha3_384, sha3_512, sha512, sha512_224, sha512_256, shake_128, shake_256, sm3
```

### HMAC
#### Con uv:
```bash
uv run python main.py hmac --algorithm sha256 --key mykey --input file.txt --encoding hex
```

#### Con pip:
```bash
python -m src.main hmac --algorithm sha256 --key mykey --input file.txt --encoding hex
```

### Generación de pares de claves
#### Con uv:
```bash
uv run python main.py keypair --type rsa --passphrase mypassphrase --out-dir ./keys --modulus-length 2048
```

#### Con pip:
```bash
python -m src.main keypair --type rsa --passphrase mypassphrase --out-dir ./keys --modulus-length 2048
```

### Firma digital
#### Con uv:
```bash
uv run python main.py sign --algorithm RSA-SHA256 --input file.txt --private-key ./keys/private.pem --passphrase mypassphrase --encoding hex
```

#### Con pip:
```bash
python -m src.main sign --algorithm RSA-SHA256 --input file.txt --private-key ./keys/private.pem --passphrase mypassphrase --encoding hex
```

### Verificación de firmas
#### Con uv:
```bash
uv run python main.py verify --algorithm RSA-SHA256 --input file.txt --public-key ./keys/public.pem --signature <signature_hex> --signature-encoding hex
```

#### Con pip:
```bash
python -m src.main verify --algorithm RSA-SHA256 --input file.txt --public-key ./keys/public.pem --signature <signature_hex> --signature-encoding hex
```

### Diffie-Hellman
#### Con uv:
```bash
uv run python main.py diffie-hellman --encoding hex
```

#### Con pip:
```bash
python -m src.main diffie-hellman --encoding hex
```

## Notas

- **uv es la forma recomendada** de gestionar este proyecto ya que maneja automáticamente el entorno virtual y las dependencias
- Con `uv run`, no necesitas activar manualmente un entorno virtual
- Este proyecto mantiene la funcionalidad del proyecto original de TypeScript
- Los archivos de claves se generan en el directorio `.secrets` por defecto
- Se recomienda usar contraseñas seguras para proteger las claves privadas

## 🎓 Créditos

- **Curso original**: [Curso de Criptografía](https://platzi.com/cursos/criptografia/) - Platzi
- **Repositorio original**: [platzi/curso-criptografia](https://github.com/platzi/curso-criptografia)
- **Adaptación a Python**: Implementación propia basada en el curso original

## Comandos útiles de uv

```bash
# Ver información del proyecto
uv show

# Actualizar dependencias
uv sync --upgrade

# Añadir nueva dependencia
uv add <package-name>

# Ejecutar cualquier comando en el entorno
uv run <command>

# Activar el entorno virtual manualmente (opcional)
uv venv --activate
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

## 🔧 Funcionalidades Implementadas

Todas las funcionalidades del proyecto original han sido portadas y mejoradas:

- ✅ **PRNG**: Generación de números aleatorios
- ✅ **Cifrado simétrico**: AES con derivación de claves
- ✅ **Hash mejorado**: 
  - Validación automática de algoritmos soportados
  - Soporte para 19+ algoritmos de hash (SHA-2, SHA-3, BLAKE2, etc.)
  - Opciones para listar algoritmos disponibles
  - Descripciones de algoritmos comunes
  - Manejo robusto de errores
- ✅ **HMAC**: Autenticación de mensajes
- ✅ **Scrypt**: Derivación de claves robusta
- ✅ **RSA**: Generación de pares de claves
- ✅ **Firma digital**: RSA-SHA256
- ✅ **Verificación**: Validación de firmas
- ✅ **Diffie-Hellman**: Intercambio de claves

### ⭐ Mejoras Específicas del Hash

Esta implementación incluye mejoras significativas sobre la versión original:

1. **Validación de Algoritmos**: 
   - Verificación automática de compatibilidad con `hashlib`
   - Mensajes de error informativos con lista de algoritmos soportados

2. **Opciones de Descubrimiento**:
   - `--list-algorithms`: Lista todos los algoritmos disponibles en el sistema
   - `--show-common`: Muestra algoritmos comunes con descripciones útiles

3. **Soporte Amplio de Algoritmos**:
   - SHA-2 familia: sha224, sha256, sha384, sha512, sha512_224, sha512_256
   - SHA-3 familia: sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256
   - BLAKE2: blake2b, blake2s
   - Otros: md5, sha1, ripemd160, sm3

4. **Manejo de Errores Robusto**:
   - Validación de archivos de entrada
   - Validación de algoritmos
   - Mensajes de error específicos y útiles

## 📝 Casos de Uso Prácticos

### Hash de Archivos

#### Verificación de Integridad
```bash
# Generar hash SHA256 de un archivo importante
uv run python main.py hash -a sha256 -i documento_importante.pdf
# Guardar el resultado para verificación posterior

# Verificar integridad después de transferencia/almacenamiento
uv run python main.py hash -a sha256 -i documento_importante.pdf
# Comparar con el hash original
```

#### Comparación de Archivos
```bash
# Comparar dos archivos generando sus hashes
uv run python main.py hash -a sha256 -i archivo1.txt
uv run python main.py hash -a sha256 -i archivo2.txt
# Si los hashes son idénticos, los archivos son idénticos
```

#### Forense Digital
```bash
# Usar algoritmos seguros para evidencia digital
uv run python main.py hash -a sha3_512 -i evidencia.img --enc hex
uv run python main.py hash -a blake2b -i evidencia.img --enc hex
# Múltiples algoritmos para mayor confianza
```

#### Elección de Algoritmo según Necesidad
```bash
# Para velocidad (archivos grandes, verificación rápida)
uv run python main.py hash -a blake2b -i archivo_grande.zip

# Para máxima seguridad (documentos críticos)
uv run python main.py hash -a sha3_512 -i contrato_importante.pdf

# Para compatibilidad legacy (sistemas antiguos)
uv run python main.py hash -a sha256 -i datos_legacy.txt

# Ver qué algoritmos están disponibles en tu sistema
uv run python main.py hash --list-algorithms
```