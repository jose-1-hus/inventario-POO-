import re
import secrets
from datetime import datetime
import hashlib


class PasswordHasher:
    """Servicio de hashing de contraseñas"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Genera hash SHA-256 de la contraseña"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verifica si la contraseña coincide con el hash"""
        return PasswordHasher.hash_password(password) == hashed


class TokenGenerator:
    """Servicio de generación de tokens únicos"""
    
    @staticmethod
    def generate_token() -> str:
        """Genera token criptográfico seguro"""
        return secrets.token_hex(16)


class Validator:
    """Servicio de validaciones"""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Valida formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def is_strong_password(password: str) -> bool:
        """Valida contraseña fuerte"""
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        return True
    
    @staticmethod
    def get_password_error(password: str) -> str:
        """Retorna mensaje de error específico"""
        if len(password) < 8:
            return "Mínimo 8 caracteres"
        if not any(c.isupper() for c in password):
            return "Incluir mayúscula"
        if not any(c.isdigit() for c in password):
            return "Incluir número"
        return ""


class Usuario:
    """Modelo de Usuario con encapsulación"""
    
    def __init__(self, id_usuario: str, email: str, password_hash: str, 
                 fecha_registro: str, access_token: str = None):
        self.__id_usuario = id_usuario
        self.__email = email
        self.__password_hash = password_hash
        self.__fecha_registro = fecha_registro
        self.__access_token = access_token
    
    # Getters
    @property
    def id_usuario(self) -> str:
        """Obtiene ID del usuario"""
        return self.__id_usuario
    
    @property
    def email(self) -> str:
        """Obtiene email del usuario"""
        return self.__email
    
    @property
    def password_hash(self) -> str:
        """Obtiene hash de contraseña"""
        return self.__password_hash
    
    @property
    def fecha_registro(self) -> str:
        """Obtiene fecha de registro"""
        return self.__fecha_registro
    
    @property
    def access_token(self) -> str:
        """Obtiene token de acceso"""
        return self.__access_token
    
    # Setters
    @access_token.setter
    def access_token(self, token: str):
        """Actualiza token de acceso"""
        self.__access_token = token


class RepositorioUsuarios:
    """Gestiona usuarios en memoria con encapsulación"""
    
    def __init__(self):
        self.__usuarios = []
    
    def obtener_por_email(self, email: str) -> Usuario:
        """Busca usuario por email"""
        for usuario in self.__usuarios:
            if usuario.email == email:
                return usuario
        return None
    
    def obtener_por_token(self, token: str) -> Usuario:
        """Busca usuario por token"""
        for usuario in self.__usuarios:
            if usuario.access_token == token:
                return usuario
        return None
    
    def crear_usuario(self, usuario: Usuario) -> bool:
        """Crea nuevo usuario"""
        if self.obtener_por_email(usuario.email):
            return False
        self.__usuarios.append(usuario)
        return True
    
    def actualizar_token(self, email: str, token: str) -> bool:
        """Actualiza token del usuario"""
        usuario = self.obtener_por_email(email)
        if usuario:
            usuario.access_token = token
            return True
        return False
    
    def obtener_todos(self) -> list:
        """Retorna copia de todos los usuarios"""
        return self.__usuarios.copy()
    
    def contar_usuarios(self) -> int:
        """Retorna cantidad de usuarios"""
        return len(self.__usuarios)


class ServicioAutenticacion:
    """Lógica de autenticación con encapsulación"""
    
    def __init__(self, repositorio: RepositorioUsuarios):
        self.__repositorio = repositorio
        self.__password_hasher = PasswordHasher()
        self.__token_generator = TokenGenerator()
        self.__validator = Validator()
    
    def registrar_usuario(self, email: str, password: str) -> tuple[bool, str]:
        """Registra nuevo usuario"""
        
        if not self.__validator.is_valid_email(email):
            return False, "Email inválido"
        
        if not self.__validator.is_strong_password(password):
            error = self.__validator.get_password_error(password)
            return False, error
        
        if self.__repositorio.obtener_por_email(email):
            return False, "Email ya registrado"
        
        usuario_id = secrets.token_hex(4)
        password_hash = self.__password_hasher.hash_password(password)
        fecha_registro = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        usuario = Usuario(usuario_id, email, password_hash, fecha_registro)
        
        if self.__repositorio.crear_usuario(usuario):
            return True, "Usuario registrado ✅"
        
        return False, "Error al registrar"
    
    def login_usuario(self, email: str, password: str) -> tuple[bool, str, str]:
        """Autentica usuario"""
        
        usuario = self.__repositorio.obtener_por_email(email)
        
        if not usuario:
            return False, "Email o contraseña incorrectos", None
        
        if not self.__password_hasher.verify_password(password, usuario.password_hash):
            return False, "Email o contraseña incorrectos", None
        
        token = self.__token_generator.generate_token()
        self.__repositorio.actualizar_token(email, token)
        
        return True, "Login exitoso ✅", token
    
    def validar_sesion(self, token: str) -> tuple[bool, Usuario]:
        """Valida token activo"""
        usuario = self.__repositorio.obtener_por_token(token)
        return usuario is not None, usuario
    
    def cerrar_sesion(self, email: str) -> bool:
        """Cierra sesión"""
        return self.__repositorio.actualizar_token(email, None)
    
    def obtener_repositorio(self) -> RepositorioUsuarios:
        """Obtiene acceso al repositorio (solo lectura de métodos públicos)"""
        return self.__repositorio


class InterfazTerminal:
    """Interfaz en terminal con encapsulación"""
    
    def __init__(self, servicio_auth: ServicioAutenticacion):
        self.__servicio_auth = servicio_auth
        self.__usuario_actual = None
        self.__token_actual = None
    
    def __limpiar_pantalla(self):
        """Limpia terminal (método privado)"""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def __mostrar_titulo(self, titulo: str):
        """Muestra título (método privado)"""
        print("\n" + "="*50)
        print(f"  {titulo.center(46)}")
        print("="*50)
    
    def __mostrar_menu_principal(self):
        """Menú principal (método privado)"""
        self.__mostrar_titulo("SISTEMA DE INVENTARIO")
        print("\n1. Registrarse")
        print("2. Iniciar sesión")
        print("3. Salir")
    
    def __mostrar_menu_sesion(self):
        """Menú con sesión activa (método privado)"""
        self.__mostrar_titulo(f"BIENVENIDO: {self.__usuario_actual.email}")
        print(f"\n📌 Código de acceso: {self.__token_actual[:12]}...")
        print(f"\nRegistrado: {self.__usuario_actual.fecha_registro}")
        print("\n1. Ver código completo")
        print("2. Ver todos los usuarios")
        print("3. Cerrar sesión")
    
    def __registrarse(self):
        """Flujo de registro (método privado)"""
        self.__mostrar_titulo("REGISTRARSE")
        
        email = input("\n📧 Email: ").strip()
        password = input("🔐 Contraseña: ").strip()
        
        if not email or not password:
            print("\n❌ Campos requeridos")
            return
        
        éxito, mensaje = self.__servicio_auth.registrar_usuario(email, password)
        print(f"\n{mensaje}")
        input("\nPresiona Enter...")
    
    def __iniciar_sesion(self):
        """Flujo de login (método privado)"""
        self.__mostrar_titulo("INICIAR SESIÓN")
        
        email = input("\n📧 Email: ").strip()
        password = input("🔐 Contraseña: ").strip()
        
        if not email or not password:
            print("\n❌ Campos requeridos")
            input("\nPresiona Enter...")
            return
        
        éxito, mensaje, token = self.__servicio_auth.login_usuario(email, password)
        
        if éxito:
            print(f"\n{mensaje}")
            self.__usuario_actual = self.__servicio_auth.obtener_repositorio().obtener_por_email(email)
            self.__token_actual = token
            self.__menu_sesion_activa()
        else:
            print(f"\n❌ {mensaje}")
            input("\nPresiona Enter...")
    
    def __menu_sesion_activa(self):
        """Menú con sesión (método privado)"""
        while True:
            self.__limpiar_pantalla()
            self.__mostrar_menu_sesion()
            
            opcion = input("\nOpción: ").strip()
            
            if opcion == "1":
                self.__mostrar_titulo("CÓDIGO DE ACCESO ÚNICO")
                print(f"\n🔐 {self.__token_actual}")
                input("\nPresiona Enter...")
            elif opcion == "2":
                self.__mostrar_titulo("USUARIOS REGISTRADOS")
                usuarios = self.__servicio_auth.obtener_repositorio().obtener_todos()
                print(f"\nTotal: {len(usuarios)}\n")
                for i, u in enumerate(usuarios, 1):
                    print(f"{i}. {u.email} ({u.fecha_registro})")
                input("\nPresiona Enter...")
            elif opcion == "3":
                if self.__servicio_auth.cerrar_sesion(self.__usuario_actual.email):
                    print("\n✅ Sesión cerrada")
                    self.__usuario_actual = None
                    self.__token_actual = None
                    input("\nPresiona Enter...")
                    break
            else:
                print("\n❌ Opción inválida")
                input("\nPresiona Enter...")
    
    def ejecutar(self):
        """Loop principal (método público)"""
        while True:
            self.__limpiar_pantalla()
            self.__mostrar_menu_principal()
            
            opcion = input("\nOpción: ").strip()
            
            if opcion == "1":
                self.__registrarse()
            elif opcion == "2":
                self.__iniciar_sesion()
            elif opcion == "3":
                print("\n👋 ¡Hasta luego!")
                break
            else:
                print("\n❌ Opción inválida")
                input("\nPresiona Enter...")


def main():
    """Función principal"""
    repositorio = RepositorioUsuarios()
    servicio_auth = ServicioAutenticacion(repositorio)
    interfaz = InterfazTerminal(servicio_auth)
    interfaz.ejecutar()


if __name__ == "__main__":
    main()
    
print ("hola")