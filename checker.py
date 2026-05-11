import hashlib
import urllib.request
import urllib.error
import sys


def sha1_hash(password: str) -> str:
    """Gera o hash SHA-1 da senha em letras maiúsculas."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_pwned(password: str) -> int:
    """
    Verifica se a senha foi exposta em algum vazamento.
    Usa a técnica k-Anonymity: apenas os primeiros 5 caracteres do hash
    são enviados à API — a senha real NUNCA sai do seu computador.
    
    Retorna o número de vezes que a senha apareceu em vazamentos (0 = segura).
    Retorna -1 em caso de erro de conexão.
    """
    full_hash = sha1_hash(password)
    prefix = full_hash[:5]
    suffix = full_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HIBP-Checker-Python"})
        with urllib.request.urlopen(req) as response:
            hashes = response.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"[ERRO] Não foi possível conectar à API: {e}")
        return -1

    for line in hashes.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def check_email_breaches(email: str) -> list:
    """
    Verifica se o e-mail aparece em vazamentos conhecidos.
    Nota: a API de e-mails da HIBP requer chave paga.
    Esta função retorna instruções para o usuário verificar manualmente.
    """
    return {
        "email": email,
        "manual_check": f"https://haveibeenpwned.com/account/{email}",
        "note": "A verificação de e-mails via API requer plano pago. Acesse o link para verificar manualmente."
    }


def display_result(password: str, count: int):
    """Exibe o resultado de forma amigável."""
    print(f"\n{'='*50}")
    print(f"  Senha verificada: {'*' * len(password)}")
    print(f"{'='*50}")

    if count == -1:
        print("  ❌ ERRO — Não foi possível verificar a senha devido a problemas de conexão.")
    elif count == 0:
        print("  ✅ SEGURA — Não encontrada em nenhum vazamento.")
    elif count < 100:
        print(f"  ⚠️  ATENÇÃO — Encontrada {count}x em vazamentos.")
        print("  Considere trocar esta senha.")
    else:
        print(f"  ❌ COMPROMETIDA — Encontrada {count:,}x em vazamentos!")
        print("  Troque esta senha IMEDIATAMENTE.")

    print(f"{'='*50}\n")


def main():
    print("\n🔐 HIBP Password Checker")
    print("Verifica se sua senha foi exposta em vazamentos de dados.")
    print("Sua senha NUNCA é enviada pela internet (k-Anonymity).\n")

    while True:
        password = input("Digite uma senha para verificar (ou 'sair' para encerrar): ").strip()

        if password.lower() == "sair":
            print("Encerrando. Mantenha suas senhas seguras! 🔒")
            break

        if not password:
            print("Por favor, digite uma senha válida.")
            continue

        print("Verificando...")
        count = check_password_pwned(password)
        display_result(password, count)

        continuar = input("Verificar outra senha? (s/n): ").strip().lower()
        if continuar != "s":
            print("Encerrando. Mantenha suas senhas seguras! 🔒")
            break


if __name__ == "__main__":
    main()
