import hashlib
import tkinter as tk
from tkinter import messagebox


# --- Funções de Hash e Verificação de Senha (do seu código original) ---
def criar_hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()


def verificar_senha(senha_digitada, hash_armazenado):
    return criar_hash_senha(senha_digitada) == hash_armazenado


# --- Simulação de um banco de dados de usuários ---
usuarios_bd = {
    "admin": criar_hash_senha("senha123"),
    "usuario1": criar_hash_senha("abc@123"),
    "teste": criar_hash_senha("teste123"),
    "WGR": criar_hash_senha("1234")
}

# --- Lógica da Interface Gráfica (Tkinter) ---


def tentar_login():
    """
    Função chamada quando o botão de login é clicado.
    Verifica as credenciais e mostra uma mensagem.
    """
    usuario = entry_usuario.get()  # Pega o texto do campo de usuário
    senha = entry_senha.get()      # Pega o texto do campo de senha

    if usuario in usuarios_bd and verificar_senha(senha, usuarios_bd[usuario]):
        messagebox.showinfo("Login Bem-Sucedido", f"Bem-vindo(a), {usuario}!")
        # Aqui você poderia fechar a janela de login e abrir a próxima tela do seu aplicativo
        janela_login.destroy() # Fecha a janela de login após o sucesso
    else:
        messagebox.showerror("Erro de Login", "Usuário ou senha inválidos.")
        entry_senha.delete(0, tk.END) # Limpa o campo da senha para nova tentativa


# --- Configuração da Janela Principal ---
janela_login = tk.Tk()
janela_login.title("Tela de Login")
janela_login.geometry("300x200") # Define o tamanho da janela (largura x altura)
janela_login.resizable(False, False) # Impede que a janela seja redimensionada

# Centralizar a janela na tela (opcional)
janela_login.update_idletasks()
width = janela_login.winfo_width()
height = janela_login.winfo_height()
x = (janela_login.winfo_screenwidth() // 2) - (width // 2)
y = (janela_login.winfo_screenheight() // 2) - (height // 2)
janela_login.geometry(f'{width}x{height}+{x}+{y}')

# --- Widgets da Interface ---

# Label e Campo para o Usuário
label_usuario = tk.Label(janela_login, text="Usuário:")
label_usuario.pack(pady=5) # Adiciona um espaçamento vertical

entry_usuario = tk.Entry(janela_login, width=30)
entry_usuario.pack(pady=5)
entry_usuario.focus_set() # Coloca o foco no campo de usuário ao iniciar

# Label e Campo para a Senha
label_senha = tk.Label(janela_login, text="Senha:")
label_senha.pack(pady=5)

entry_senha = tk.Entry(janela_login, width=30, show="*") # 'show="*"' esconde a senha digitada
entry_senha.pack(pady=5)

# Botão de Login
button_login = tk.Button(janela_login, text="Login", command=tentar_login)
button_login.pack(pady=10)

# Vincula a tecla Enter ao botão de login (opcional, para conveniência)
janela_login.bind('<Return>', lambda event=None: tentar_login())


# --- Iniciar o Loop Principal da Interface ---
janela_login.mainloop()