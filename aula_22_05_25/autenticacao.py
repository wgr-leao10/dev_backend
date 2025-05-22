import hashlib


def criar_hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()


def verificar_senha(senha_digitada, hash_armazenado):
    return criar_hash_senha(senha_digitada) == hash_armazenado


# Simulação de um banco de dados de usuários
usuarios_bd = {
    "admin": criar_hash_senha("senha123"),
    "usuario1": criar_hash_senha("abc@123")
}

# Tentativa de login
usuario_login = "admin"
senha_login = "senha123"

if usuario_login in usuarios_bd and verificar_senha(senha_login, usuarios_bd[usuario_login]):
    print(f"Usuário '{usuario_login}' autenticado com sucesso!")
else:
    print("Usuário ou senha inválidos.")

# Tentativa de login com senha incorreta
usuario_login_errado = "usuario1"
senha_login_errada = "senha_incorreta"

if usuario_login_errado in usuarios_bd and verificar_senha(senha_login_errada, usuarios_bd[usuario_login_errado]):
    print(f"Usuário '{usuario_login_errado}' autenticado com sucesso!")
else:
    print(f"Falha na autenticação para o usuário '{usuario_login_errado}'.")
