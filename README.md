# password-checker🔐

Verifica se uma senha já vazou em algum lugar da internet, usando a API do [Have I Been Pwned](https://haveibeenpwned.com/). Sem mandar a senha real pra nenhum servidor.

## como funciona

A técnica usada aqui se chama **k-Anonymity**. O script gera um hash SHA-1 da senha localmente e manda só os primeiros 5 caracteres pra API. Ela devolve uma lista de hashes parecidos e a comparação acontece no seu computador. Nem a HIBP sabe o que você digitou.

```
senha: "minhasenha123"
hash: 4B4E2F4A8C...
o que vai pra API: "4B4E2"
```

## código

### sha1_hash

```python
def sha1_hash(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
```

Transforma a senha em um hash SHA-1. O `.encode("utf-8")` converte a string pra bytes, que é o formato que o SHA-1 aceita. O resultado vem em maiúsculo pra bater com o formato que a API devolve.

---

### check_password_pwned

```python
def check_password_pwned(password: str) -> int:
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
```

Aqui mora o k-Anonymity na prática. O hash é dividido em dois pedaços: os primeiros 5 caracteres (`prefix`) vão pra API e o resto (`suffix`) fica local. A API devolve uma lista de hashes que começam com aquele prefixo, podendo ser centenas. O script percorre essa lista e verifica se algum termina igual ao `suffix`. Se encontrar, retorna quantas vezes aquela senha apareceu em vazamentos. Se não encontrar, retorna 0. Em caso de erro de conexão, retorna -1 em vez de derrubar o programa inteiro.

---

### display_result

```python
def display_result(password: str, count: int):
    print(f"\n{'='*50}")
    print(f"  Senha verificada: {'*' * len(password)}")
    print(f"{'='*50}")

    if count == -1:
        print("  Erro de conexão. Tente novamente.")
    elif count == 0:
        print("  Segura, não apareceu em nenhum vazamento.")
    elif count < 100:
        print(f"  Atenção, apareceu {count}x em vazamentos. Considere trocar.")
    else:
        print(f"  Comprometida, apareceu {count:,}x. Troca agora.")

    print(f"{'='*50}\n")
```

Formata e exibe o resultado. A senha aparece mascarada com asteriscos (`'*' * len(password)`) pra não expor o que foi digitado. O resultado tem três níveis: segura, atenção e comprometida. Qualquer senha acima de 100 ocorrências já é sinal de que é muito comum e deve ser trocada.

---

### main

```python
def main():
    print("\n🔐 HIBP Password Checker")
    print("Sua senha nunca sai do seu computador.\n")

    while True:
        password = input("Digite uma senha (ou 'sair'): ").strip()

        if password.lower() == "sair":
            break

        if not password:
            continue

        count = check_password_pwned(password)
        display_result(password, count)

        if input("Verificar outra? (s/n): ").strip().lower() != "s":
            break


if __name__ == "__main__":
    main()
```

O loop principal. O `.strip()` remove espaços acidentais no começo e fim do que foi digitado. O `if __name__ == "__main__"` garante que o `main()` só roda quando o arquivo é executado diretamente, então se alguém importar o script em outro projeto as funções ficam disponíveis sem executar nada automaticamente.


## o que aprendi

SHA-1 é considerado fraco pra criptografia mas funciona bem aqui porque o objetivo é só anonimizar a consulta, não proteger a senha em si. Aprendi também que `sys.exit()` dentro de uma função é má prática porque quebra qualquer código que tente importar ela. O certo é retornar um valor de erro e deixar quem chamou decidir o que fazer.

## próximos passos

- interface web com Flask
- verificar uma lista de senhas de um arquivo `.txt`
- testes com `pytest`

## referências

[HIBP API](https://haveibeenpwned.com/API/v3#PwnedPasswords) · [k-Anonymity na prática, Cloudflare](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/) · [NIST sobre senhas](https://pages.nist.gov/800-63-3/sp800-63b.html)
