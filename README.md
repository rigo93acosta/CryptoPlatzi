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
uv run python main.py hash --algorithm sha256 --input file.txt --encoding hex
```

#### Con pip:
```bash
python -m src.main hash --algorithm sha256 --input file.txt --encoding hex
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

Todas las funcionalidades del proyecto original han sido portadas:

- ✅ **PRNG**: Generación de números aleatorios
- ✅ **Cifrado simétrico**: AES con derivación de claves
- ✅ **Hash**: SHA-256, SHA-512, etc.
- ✅ **HMAC**: Autenticación de mensajes
- ✅ **Scrypt**: Derivación de claves robusta
- ✅ **RSA**: Generación de pares de claves
- ✅ **Firma digital**: RSA-SHA256
- ✅ **Verificación**: Validación de firmas
- ✅ **Diffie-Hellman**: Intercambio de claves