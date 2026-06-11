import sys
import os
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from sha256_impl import sha256 as _sha256_pure


def compute_hash(filepath: str) -> str:
    """Calcula o hash SHA256 de um arquivo usando a implementação pura."""
    with open(filepath, "rb") as f:
        data = f.read()
    return _sha256_pure(data)


def cmd_hash(args):
    """Exibe o hash SHA256 de um ou mais arquivos."""
    exit_code = 0
    for filepath in args.files:
        p = Path(filepath)
        if not p.exists():
            print(f"ERRO: arquivo não encontrado: {filepath}", file=sys.stderr)
            exit_code = 1
            continue
        if not p.is_file():
            print(f"ERRO: não é um arquivo: {filepath}", file=sys.stderr)
            exit_code = 1
            continue
        hash_val = compute_hash(filepath)
        print(f"{hash_val}  {filepath}")
    sys.exit(exit_code)


def cmd_verify(args):
    """Verifica se o hash SHA256 de um arquivo corresponde ao valor esperado."""
    filepath = args.file
    expected = args.expected_hash.lower().strip()

    if len(expected) != 64 or not all(c in "0123456789abcdef" for c in expected):
        print("ERRO: o hash fornecido não é um SHA256 válido (deve ter 64 caracteres hexadecimais).",
              file=sys.stderr)
        sys.exit(2)

    p = Path(filepath)
    if not p.exists():
        print(f"ERRO: arquivo não encontrado: {filepath}", file=sys.stderr)
        sys.exit(1)

    computed = compute_hash(filepath)

    if computed == expected:
        print(f"OK        {filepath}")
        print(f"Hash:     {computed}")
        sys.exit(0)
    else:
        print(f"FALHA     {filepath}")
        print(f"Esperado: {expected}")
        print(f"Calculado:{computed}")
        sys.exit(1)


def cmd_generate(args):
    """Gera um arquivo de checksums .sha256."""
    output_path = args.output or "checksums.sha256"
    lines = []

    for filepath in args.files:
        p = Path(filepath)
        if not p.exists():
            print(f"AVISO: arquivo não encontrado, ignorado: {filepath}", file=sys.stderr)
            continue
        if not p.is_file():
            print(f"AVISO: não é um arquivo, ignorado: {filepath}", file=sys.stderr)
            continue
        hash_val = compute_hash(filepath)
        line = f"{hash_val}  {filepath}"
        lines.append(line)
        print(line)

    if not lines:
        print("ERRO: nenhum arquivo válido fornecido.", file=sys.stderr)
        sys.exit(1)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\nArquivo de checksums salvo em: {output_path}")


def cmd_check(args):
    """Verifica múltiplos arquivos a partir de um arquivo .sha256."""
    checksum_file = args.checksum_file

    if not Path(checksum_file).exists():
        print(f"ERRO: arquivo de checksums não encontrado: {checksum_file}", file=sys.stderr)
        sys.exit(1)

    ok_count = 0
    fail_count = 0
    missing_count = 0

    with open(checksum_file, "r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(None, 1)
            if len(parts) != 2:
                print(f"AVISO: linha {line_num} inválida, ignorada: {raw_line!r}",
                      file=sys.stderr)
                continue

            expected_hash, filepath = parts[0].lower(), parts[1].strip()

            if not Path(filepath).exists():
                print(f"NÃO ENCONTRADO  {filepath}")
                missing_count += 1
                continue

            computed = compute_hash(filepath)
            if computed == expected_hash:
                print(f"OK              {filepath}")
                ok_count += 1
            else:
                print(f"FALHA           {filepath}")
                fail_count += 1

    print(f"\nResumo: {ok_count} OK, {fail_count} falha(s), {missing_count} não encontrado(s)")

    if fail_count > 0 or missing_count > 0:
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="sha256_verifier",
        description="Verificador de integridade de arquivos usando SHA256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
exemplos:
  Calcular hash de um arquivo:
    python sha256_verifier.py hash documento.pdf

  Calcular hashes de vários arquivos:
    python sha256_verifier.py hash arq1.txt arq2.zip

  Verificar arquivo contra hash conhecido:
    python sha256_verifier.py verify documento.pdf abc123...def

  Gerar arquivo de checksums:
    python sha256_verifier.py generate arq1.txt arq2.zip -o meus.sha256

  Verificar múltiplos arquivos de uma vez:
    python sha256_verifier.py check meus.sha256
""",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMANDO")
    sub.required = True

    p_hash = sub.add_parser("hash", help="Calcular hash SHA256 de arquivo(s)")
    p_hash.add_argument("files", nargs="+", metavar="ARQUIVO", help="Arquivo(s) a hashar")

    p_verify = sub.add_parser("verify", help="Verificar arquivo contra hash conhecido")
    p_verify.add_argument("file", metavar="ARQUIVO", help="Arquivo a verificar")
    p_verify.add_argument("expected_hash", metavar="HASH", help="Hash SHA256 esperado (64 hex)")

    p_gen = sub.add_parser("generate", help="Gerar arquivo de checksums .sha256")
    p_gen.add_argument("files", nargs="+", metavar="ARQUIVO", help="Arquivo(s) a incluir")
    p_gen.add_argument("-o", "--output", metavar="SAIDA",
                       help="Nome do arquivo de saída (padrão: checksums.sha256)")

    p_check = sub.add_parser("check", help="Verificar arquivos a partir de um .sha256")
    p_check.add_argument("checksum_file", metavar="ARQUIVO.sha256",
                         help="Arquivo de checksums a verificar")

    return parser


def main():
    """Ponto de entrada: parseia argumentos e despacha para o subcomando correto."""
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "hash": cmd_hash,
        "verify": cmd_verify,
        "generate": cmd_generate,
        "check": cmd_check,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
