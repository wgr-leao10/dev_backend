import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog
import random
import json # Para "simular" serialização/deserialização de tokens


# --- Funções de Hash e Verificação de Senha (Local, mas seria usada pelo AuthService) ---
def criar_hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()


def verificar_senha(senha_digitada, hash_armazenado):
    return criar_hash_senha(senha_digitada) == hash_armazenado


# --- Microsserviço Simulado: UserService (Armazena dados de usuários) ---
# Em um cenário real, este seria um serviço de BD ou um microsserviço separado.
_users_data = {
    "admin": {
        "hash_senha": criar_hash_senha("admin123"),
        "nivel_acesso": "admin",
        "2fa_ativado": True
    },
    "editor": {
        "hash_senha": criar_hash_senha("editor123"),
        "nivel_acesso": "editor",
        "2fa_ativado": False
    },
    "usuario": {
        "hash_senha": criar_hash_senha("user123"),
        "nivel_acesso": "user",
        "2fa_ativado": True
    },
    "dev": {
        "hash_senha": criar_hash_senha("devpass"),
        "nivel_acesso": "admin",
        "2fa_ativado": False
    }
}


class UserService:
    """Simula um microsserviço de usuários."""
    def get_user_data(self, username):
        print(f"[UserService] Tentando obter dados para: {username}")
        # Em um ambiente real, isso faria uma consulta a um banco de dados
        return _users_data.get(username)


# --- Microsserviço Simulado: AuthService (Autentica e gera tokens) ---
class AuthService:
    """Simula um microsserviço de autenticação que interage com o UserService."""
    def __init__(self, user_service):
        self.user_service = user_service
        self.secret_key = "super_secreta_chave_para_token" # Chave para "assinar" o token

    def authenticate(self, username, password):
        print(f"[AuthService] Tentando autenticar: {username}")
        user_data = self.user_service.get_user_data(username)

        if not user_data:
            print(f"[AuthService] Usuário '{username}' não encontrado.")
            return None, False, "Usuário não encontrado." # Token, 2FA_required, message

        if verificar_senha(password, user_data["hash_senha"]):
            print(f"[AuthService] Senha correta para '{username}'.")
            
            # Simula a criação de um JWT. Em real, seria um JWT assinado.
            # Este "token" é um dicionário com informações básicas.
            payload = {
                "user": username,
                "role": user_data["nivel_acesso"],
                "2fa_required": user_data.get("2fa_ativado", False),
                "exp": int(time.time()) + 3600 # Expiração simulada em 1 hora
            }
            # Simula a "assinatura" do token adicionando uma hash simples
            # Em real, usaria JWT library (pyjwt)
            payload_str = json.dumps(payload)
            signature = hashlib.sha256((payload_str + self.secret_key).encode()).hexdigest()
            token = {"payload": payload, "signature": signature}

            return token, user_data.get("2fa_ativado", False), "Autenticação primária bem-sucedida."
        else:
            print(f"[AuthService] Senha incorreta para '{username}'.")
            return None, False, "Credenciais inválidas."


# --- Microsserviço Simulado: AppService (Verifica tokens e fornece recursos) ---
class AppService:
    """Simula um microsserviço de aplicação que consome o token."""
    def __init__(self, user_service):
        self.user_service = user_service
        self.secret_key = "super_secreta_chave_para_token" # Mesma chave para validar a "assinatura"

    def validate_token(self, token):
        print(f"[AppService] Validando token: {token}")
        if not token or "payload" not in token or "signature" not in token:
            return False, "Token inválido ou malformado."

        payload = token["payload"]
        signature = token["signature"]

        # Verifica a "assinatura"
        expected_signature = hashlib.sha256((json.dumps(payload) + self.secret_key).encode()).hexdigest()
        if signature != expected_signature:
            print("[AppService] Assinatura do token inválida.")
            return False, "Assinatura do token inválida."
        
        # Verifica a expiração (simulada)
        if payload.get("exp", 0) < int(time.time()):
            print("[AppService] Token expirado.")
            return False, "Token expirado."

        # Verifica se o usuário do token ainda existe no UserService (revogação, etc.)
        user_data = self.user_service.get_user_data(payload.get("user"))
        if not user_data:
            print(f"[AppService] Usuário '{payload.get('user')}' do token não encontrado no UserService.")
            return False, "Usuário do token não encontrado ou revogado."

        return True, payload # Retorna True e o payload do token se válido

    def get_user_permissions(self, token):
        is_valid, data = self.validate_token(token)
        if is_valid:
            print(f"[AppService] Token válido. Nível de acesso: {data['role']}")
            return data["user"], data["role"]
        return None, None


# --- Inicialização dos "Microsserviços" ---
user_service = UserService()
auth_service = AuthService(user_service)
app_service = AppService(user_service)

# --- Variáveis globais para 2FA e Token ---
_otp_gerado = ""
_current_session_token = None # Armazena o token após o login completo

# --- Funções para a Interface Gráfica (GUI) ---


def exibir_tela_principal(token):
    """
    Cria e exibe uma nova janela simulando a tela principal do sistema,
    com base no nível de acesso do usuário do token.
    """
    is_valid, payload = app_service.validate_token(token)
    if not is_valid:
        messagebox.showerror("Erro de Acesso", f"Token inválido ou expirado: {payload}")
        janela_login.deiconify()
        return

    usuario_logado = payload["user"]
    nivel_acesso = payload["role"]

    tela_principal = tk.Toplevel(janela_login)
    tela_principal.title(f"Sistema - Logado como: {usuario_logado} ({nivel_acesso.upper()})")
    tela_principal.geometry("400x250")
    tela_principal.grab_set()

    tk.Label(tela_principal, text=f"Bem-vindo(a), {usuario_logado}!", font=("Arial", 14, "bold")).pack(pady=20)
    tk.Label(tela_principal, text=f"Seu nível de acesso é: {nivel_acesso.upper()}", font=("Arial", 12)).pack(pady=10)

    # Conteúdo específico por nível de acesso
    if nivel_acesso == "admin":
        tk.Label(tela_principal, text="Você tem acesso total: Gerenciar usuários, configurações, etc.").pack()
        tk.Button(tela_principal, text="Painel de Administração", command=lambda: messagebox.showinfo("Acesso", "Abrindo painel de administração...")).pack(pady=5)
    elif nivel_acesso == "editor":
        tk.Label(tela_principal, text="Você pode criar e editar conteúdo.").pack()
        tk.Button(tela_principal, text="Gerenciar Artigos", command=lambda: messagebox.showinfo("Acesso", "Abrindo gerenciador de artigos...")).pack(pady=5)
    elif nivel_acesso == "user":
        tk.Label(tela_principal, text="Você tem acesso básico para visualização.").pack()
        tk.Button(tela_principal, text="Ver Meu Perfil", command=lambda: messagebox.showinfo("Acesso", "Abrindo perfil do usuário...")).pack(pady=5)
    
    def fazer_logout():
        global _current_session_token
        _current_session_token = None # Invalida o token da sessão
        tela_principal.destroy()
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()

    tk.Button(tela_principal, text="Logout", command=fazer_logout).pack(pady=20)


def gerar_otp():
    """Gera um código OTP de 6 dígitos."""
    return str(random.randint(100000, 999999))


def verificar_otp_gui(auth_token_payload_from_2fa):
    """
    Exibe a janela para o usuário digitar o OTP e verifica.
    """
    global _otp_gerado, _current_session_token

    _otp_gerado = gerar_otp()
    
    # Exibe o OTP para o usuário (simulando envio)
    messagebox.showinfo("Código 2FA (SIMULAÇÃO)", f"Seu código 2FA é: {_otp_gerado}\n(Este código expira em 60 segundos na vida real)")

    otp_digitado = simpledialog.askstring("Verificação 2FA", "Digite o código 2FA:", parent=janela_login)

    if otp_digitado is None:
        messagebox.showerror("Login Cancelado", "Autenticação 2FA cancelada.")
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()
        return

    if otp_digitado == _otp_gerado:
        messagebox.showinfo("2FA Concluído", "Código 2FA verificado com sucesso!")
        # Se o OTP estiver correto, finaliza o login com o token.
        # Agora o token completo (_current_session_token) é validado pelo AppService
        _current_session_token = auth_token_payload_from_2fa # Armazena o token recebido do AuthService
        exibir_tela_principal(_current_session_token)
    else:
        messagebox.showerror("Erro 2FA", "Código 2FA inválido.")
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()


def tentar_login():
    """
    Função principal da GUI.
    Interage com o AuthService para autenticar e, se necessário, com o 2FA.
    """
    global _current_session_token

    usuario = entry_usuario.get()
    senha = entry_senha.get()

    # Comunicação com o AuthService
    token, two_fa_required, message = auth_service.authenticate(usuario, senha)

    if token:
        if two_fa_required:
            messagebox.showinfo("Autenticação Necessária", message + " Requer 2FA.")
            janela_login.withdraw()
            # Passa o token recebido do AuthService para a função de verificação do 2FA
            verificar_otp_gui(token)
        else:
            messagebox.showinfo("Login Bem-Sucedido", message)
            _current_session_token = token # Armazena o token recebido do AuthService
            janela_login.withdraw()
            exibir_tela_principal(_current_session_token) # Passa o token para a tela principal
    else:
        messagebox.showerror("Erro de Login", message)
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()


# --- Configuração da Janela Principal de Login ---
janela_login = tk.Tk()
janela_login.title("Login com Microsserviços Simulado & 2FA")
janela_login.geometry("350x250")
janela_login.resizable(False, False)

# Centralizar a janela na tela
janela_login.update_idletasks()
width = janela_login.winfo_width()
height = janela_login.winfo_height()
x = (janela_login.winfo_screenwidth() // 2) - (width // 2)
y = (janela_login.winfo_screenheight() // 2) - (height // 2)
janela_login.geometry(f'{width}x{height}+{x}+{y}')

# --- Widgets da Interface ---
tk.Label(janela_login, text="Login do Sistema (Microsserviços)", font=("Arial", 14, "bold")).pack(pady=15)

label_usuario = tk.Label(janela_login, text="Usuário:")
label_usuario.pack()
entry_usuario = tk.Entry(janela_login, width=35)
entry_usuario.pack(pady=5)
entry_usuario.focus_set()

label_senha = tk.Label(janela_login, text="Senha:")
label_senha.pack()
entry_senha = tk.Entry(janela_login, width=35, show="*")
entry_senha.pack(pady=5)

button_login = tk.Button(janela_login, text="Login", command=tentar_login, font=("Arial", 10, "bold"))
button_login.pack(pady=15)

# Vincula a tecla Enter ao botão de login
janela_login.bind('<Return>', lambda event=None: tentar_login())

# --- Iniciar o Loop Principal da Interface ---
janela_login.mainloop()