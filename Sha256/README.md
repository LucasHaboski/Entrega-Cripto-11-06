# Verificador de Arquivos SHA256

Trabalho prático para a matéria de **Criptografia**.

Ferramenta de linha de comando em Python para calcular e verificar hashes SHA256 de arquivos, garantindo sua integridade.

---

## O que é SHA256?

SHA256 (Secure Hash Algorithm 256-bit) é uma função de hash criptográfico da família SHA-2, padronizada pelo NIST (FIPS PUB 180-4). Ela recebe uma entrada de tamanho arbitrário e produz sempre uma saída de 256 bits (64 caracteres hexadecimais).

**Propriedades fundamentais:**
- **Determinismo:** o mesmo arquivo sempre produz o mesmo hash
- **Efeito avalanche:** uma mudança de 1 bit na entrada altera ~50% dos bits do hash
- **Resistência à pré-imagem:** é computacionalmente inviável recuperar a mensagem original a partir do hash
- **Resistência à colisão:** é computacionalmente inviável encontrar dois arquivos com o mesmo hash

**Uso prático:** verificar que um arquivo não foi corrompido ou adulterado durante transferência ou armazenamento.

---

## Estrutura do Projeto

```
Sha256/
├── sha256_verifier.py       # Ferramenta CLI principal (usa hashlib)
├── sha256_impl.py           # Implementação SHA256 do zero (educacional)
├── test_sha256_verifier.py  # Testes automatizados (pytest)
└── README.md                # Esta documentação
```

---

## Requisitos

- Python 3.8 ou superior
- Para rodar os testes: `pip install pytest`

---

## Como Usar

### Calcular o hash de um arquivo

```bash
python sha256_verifier.py hash documento.pdf
```

Saída:
```
3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b  documento.pdf
```

### Calcular hash de vários arquivos

```bash
python sha256_verifier.py hash arq1.txt arq2.zip imagem.png
```

### Verificar um arquivo contra um hash conhecido

Use isso para confirmar que um arquivo baixado é autêntico:

```bash
python sha256_verifier.py verify documento.pdf 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
```

Saída em caso de sucesso:
```
OK        documento.pdf
Hash:     3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
```

Saída em caso de falha (arquivo adulterado):
```
FALHA     documento.pdf
Esperado: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
Calculado:aabbcc...
```

### Gerar um arquivo de checksums

Para distribuir um conjunto de arquivos com seus hashes:

```bash
python sha256_verifier.py generate arq1.txt arq2.zip -o meus_arquivos.sha256
```

Isso cria `meus_arquivos.sha256` no formato padrão `sha256sum`:
```
abc123...  arq1.txt
def456...  arq2.zip
```

### Verificar múltiplos arquivos de uma vez

```bash
python sha256_verifier.py check meus_arquivos.sha256
```

Saída:
```
OK              arq1.txt
OK              arq2.zip

Resumo: 2 OK, 0 falha(s), 0 não encontrado(s)
```

---

## Implementação SHA256 do Zero (`sha256_impl.py`)

O arquivo `sha256_impl.py` contém uma implementação completa do SHA256 em Python puro, sem usar `hashlib`. Serve para fins educacionais e demonstra cada etapa do algoritmo:

1. **Padding** — a mensagem é preenchida até ser múltiplo de 512 bits
2. **Schedule de mensagem W** — 64 palavras de 32 bits derivadas do bloco
3. **64 rounds de compressão** — usando as funções Ch, Maj, Σ0, Σ1, σ0, σ1
4. **Produção do digest** — concatenação dos 8 valores de hash de 32 bits

Para executar a demonstração:

```bash
python sha256_impl.py
```

Saída esperada (comparação com vetores NIST):
```
================================================================
SHA256 — Implementação Educacional vs hashlib (NIST test vectors)
================================================================
  [PASS] b''
  [PASS] b'abc'
  [PASS] b'abcdbcde'...
================================================================
Resultado: TODOS OK
```

---

## Testes Automatizados

```bash
pip install pytest
pytest test_sha256_verifier.py -v
```

Os testes cobrem:
- Hashes contra vetores de teste do NIST
- Comparação entre `sha256_impl` e `hashlib` em múltiplos casos
- Verificação do efeito avalanche (1 bit muda → hash diferente)
- Ciclo completo: geração e verificação de arquivo `.sha256`
- Padding: comprimento sempre múltiplo de 512 bits

---

## Compatibilidade

O formato dos arquivos `.sha256` gerados é compatível com a ferramenta `sha256sum` do Linux/macOS:

```bash
# Linux/macOS
sha256sum -c meus_arquivos.sha256
```

---

## Referências

- NIST FIPS PUB 180-4 — Secure Hash Standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- RFC 6234 — US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
