# Criptografia — Implementações Educacionais

Implementações em Python puro de SHA256, RSA e chat com criptografia ponta a ponta.

## Requisitos

```
pip install flask requests pytest
```

---

## SHA256

### Rodar o algoritmo básico

```
python Sha256/sha256_impl.py
```

Executa os vetores de teste NIST e compara com a biblioteca `hashlib`.

### Autenticador de arquivo

Calcular o hash de um arquivo:

```
python Sha256/sha256_verifier.py hash <arquivo>
```

Verificar um arquivo contra um hash conhecido:

```
python Sha256/sha256_verifier.py verify <arquivo> <hash>
```

Gerar arquivo de checksums:

```
python Sha256/sha256_verifier.py generate <arquivo1> <arquivo2> -o checksums.sha256
```

Verificar múltiplos arquivos de uma vez:

```
python Sha256/sha256_verifier.py check checksums.sha256
```

### Rodar os testes

```
pytest Sha256/test_sha256_verifier.py -v
```

---

## RSA

### Rodar o algoritmo básico

```
python RSA/rsa_impl.py
```

Gera um par de chaves, cifra e decifra mensagens de teste e demonstra assinatura digital.

### Rodar os testes

```
pytest RSA/test_rsa_impl.py -v
```

---

## Chat E2E (RSA)

O chat usa RSA para cifrar as mensagens e assinar. O servidor nunca vê o conteúdo.

### 1. Iniciar o servidor

```
python Chat/chat_server.py
```

### 2. Iniciar os clientes (em terminais separados)

```
python Chat/chat_client.py Kelvi
python Chat/chat_client.py Ryann
```

### 3. Enviar mensagem

No terminal do cliente, use o formato:

```
<destinatario>: <mensagem>
```

Exemplo:

Kelvi: olá, tudo bem?

### Outros comandos

| Comando       | Ação                     |
| ------------- | -------------------------- |
| `/usuarios` | lista usuários conectados |
| `/sair`     | encerra o cliente          |
