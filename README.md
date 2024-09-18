import tkinter as tk
from tkinter import messagebox, font

import re
from functools import partial

class PegasusChkLogin:
    def __init__(self, master):
        self.master = master
        master.title("Pegasus Chk Secure Login")
        master.geometry("400x300")
        master.configure(bg='#1a1a2e')

        self.custom_font = font.Font(family="Courier", size=12, weight="bold")

        self.frame = tk.Frame(master, bg='#16213e', pady=20, padx=20)
        self.frame.place(relx=0.5, rely=0.5, anchor='center')

        self.label_title = tk.Label(self.frame, text="PEGASUS CHK", font=("Courier", 20, "bold"), fg='#e94560', bg='#16213e')
        self.label_title.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        self.label_username = tk.Label(self.frame, text="Usuario:", font=self.custom_font, fg='#0f3460', bg='#16213e')
        self.label_username.grid(row=1, column=0, sticky='e', padx=5, pady=5)

        self.entry_username = tk.Entry(self.frame, font=self.custom_font, bg='#0f3460', fg='white', insertbackground='white')
        self.entry_username.grid(row=1, column=1, padx=5, pady=5)

        self.label_password = tk.Label(self.frame, text="Contraseña:", font=self.custom_font, fg='#0f3460', bg='#16213e')
        self.label_password.grid(row=2, column=0, sticky='e', padx=5, pady=5)

        self.entry_password = tk.Entry(self.frame, show="*", font=self.custom_font, bg='#0f3460', fg='white', insertbackground='white')
        self.entry_password.grid(row=2, column=1, padx=5, pady=5)

        self.login_button = tk.Button(self.frame, text="Iniciar sesión", command=partial(self.check_login, max_attempts=3), 
                                      bg='#e94560', fg='white', font=self.custom_font, 
                                      activebackground='#0f3460', activeforeground='white')
        self.login_button.grid(row=3, column=0, columnspan=2, pady=20)

        self.attempt_count = 0

    def check_login(self, max_attempts):
        self.attempt_count += 1
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not self.validate_input(username, password):
            return

        # En un sistema real, obtendrías el hash almacenado para este usuario de una base de datos
        stored_hash = b'$2b$12$9vWjYMYEqFQh3HLRydtLK.qmMq8LzSha2sNYCrG8wRnsdHHH5.MXK'  # Hash de "pegasus_chk_123"

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            messagebox.showinfo("Éxito", "Bienvenido al sistema Pegasus Chk")
            self.master.quit()
        else:
            if self.attempt_count >= max_attempts:
                messagebox.showerror("Error", "Demasiados intentos fallidos. El sistema se cerrará.")
                self.master.quit()
            else:
                messagebox.showerror("Error", f"Usuario o contraseña incorrectos. Intento {self.attempt_count} de {max_attempts}")

    def validate_input(self, username, password):
        if not username or not password:
            messagebox.showerror("Error", "Por favor, ingrese tanto el usuario como la contraseña.")
            return False
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            messagebox.showerror("Error", "El nombre de usuario solo puede contener letras, números y guiones bajos.")
            return False
        if len(password) < 8:
            messagebox.showerror("Error", "La contraseña debe tener al menos 8 caracteres.")
            return False
        return True

root = tk.Tk()
pegasus_login = PegasusChkLogin(root)
root.mainloop()
