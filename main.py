#importssss
import kivy
kivy.require("2.3.0")
import threading
import socket
import whois
import requests
import hashlib
import platform
import subprocess
from kivy.clock import Clock
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.properties import ObjectProperty
from kivy.storage.jsonstore import JsonStore
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.screenmanager import Screen, ScreenManager

class LoginScreen(Screen):
    username_input = ObjectProperty(None)
    password_input = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.store = JsonStore("user_data.json")

        layout = BoxLayout(
            orientation="vertical",
            padding=[50, 100, 50, 20],
            spacing=15,
            size_hint=(None, None),
        )
        layout.width = 750
        layout.height = 450

        #bemvindoaoapp
        welcome_label = Label(
            text="Welcome to PentBox!", font_size="30sp", size_hint_y=None, height=50
        )
        layout.add_widget(welcome_label)

        #cadastro
        layout.add_widget(Label(text="Usuário:", size_hint_y=None, height=30))
        self.username_input = TextInput(multiline=False, size_hint_y=None, height=40)
        layout.add_widget(self.username_input)

        #senha
        layout.add_widget(Label(text="Senha:", size_hint_y=None, height=30))
        self.password_input = TextInput(
            password=True, multiline=False, size_hint_y=None, height=40
        )
        layout.add_widget(self.password_input)

        #butaologgin
        login_button = Button(text="Login", size_hint_y=None, height=50)
        login_button.bind(on_press=self.do_login)
        layout.add_widget(login_button)

        #criaraconta
        create_account_button = Button(
            text="Criar Usuário", size_hint_y=None, height=50
        )
        create_account_button.bind(on_press=self.go_to_create_account)
        layout.add_widget(create_account_button)

        anchor = AnchorLayout(anchor_x="center", anchor_y="top")
        anchor.add_widget(layout)
        self.add_widget(anchor)

    def do_login(self, instance):
        username = self.username_input.text
        password = self.password_input.text

        if self.store.exists(username):
            if self.store.get(username)["password"] == password:
                self.manager.current = "home"
            else:
                self.show_message("Senha incorreta!")
        else:
            self.show_message("Usuário não encontrado!")

    def go_to_create_account(self, instance):
        self.manager.current = "create_account"

    def show_message(self, message):
        print(message)


class CreateAccountScreen(Screen):
    def __init__(self, **kwargs):
        super(CreateAccountScreen, self).__init__(**kwargs)
        self.store = JsonStore("user_data.json")

        layout = BoxLayout(
            orientation="vertical",
            padding=[50, 100, 50, 20],
            spacing=15,
            size_hint=(None, None),
        )
        layout.width = 750
        layout.height = 450

        layout.add_widget(
            Label(
                text="Criar Nova Conta", font_size="25sp", size_hint_y=None, height=50
            )
        )

        layout.add_widget(Label(text="Novo Usuário:", size_hint_y=None, height=30))
        self.new_username_input = TextInput(
            multiline=False, size_hint_y=None, height=40
        )
        layout.add_widget(self.new_username_input)

        layout.add_widget(Label(text="Nova Senha:", size_hint_y=None, height=30))
        self.new_password_input = TextInput(
            password=True, multiline=False, size_hint_y=None, height=40
        )
        layout.add_widget(self.new_password_input)

        create_button = Button(text="Criar Conta", size_hint_y=None, height=50)
        create_button.bind(on_press=self.create_account)
        layout.add_widget(create_button)

        back_button = Button(text="Voltar ao Login", size_hint_y=None, height=50)
        back_button.bind(on_press=self.go_to_login)
        layout.add_widget(back_button)

        anchor = AnchorLayout(anchor_x="center", anchor_y="top")
        anchor.add_widget(layout)
        self.add_widget(anchor)

    def create_account(self, instance):
        username = self.new_username_input.text
        password = self.new_password_input.text

        if username and password:
            if not self.store.exists(username):
                self.store.put(username, password=password)
                self.show_message("Conta criada com sucesso!")
                self.manager.current = "login"
            else:
                self.show_message("Usuário já existe!")
        else:
            self.show_message("Preencha todos os campos!")

    def go_to_login(self, instance):
        self.manager.current = "login"

    def show_message(self, message):
        print(message)


class HomeScreen(Screen):
    def __init__(self, **kwargs):
        super(HomeScreen, self).__init__(**kwargs)

        main_layout = BoxLayout(orientation="vertical", padding=20, spacing=10)

        welcome_label = Label(
            text="Home", font_size="30sp", size_hint_y=None, height=50
        )
        main_layout.add_widget(welcome_label)

        buttons_layout = GridLayout(cols=2, spacing=10, size_hint_y=1)

        #butoeshome
        buttons = [
            ("PortScanner", self.go_to_port_scanner),
            ("Whois LookUp", self.go_to_whois_lookup),
            ("IP GeoLocation", self.go_to_ip_geolocation),
            ("Hash Identifier", self.go_to_hash_identifier),
            ("Ping", self.go_to_ping),
            ("Sobre", self.go_to_sobre),
        ]

        for text, callback in buttons:
            btn = Button(text=text, size_hint_y=None, height=60)
            btn.bind(on_press=callback)
            buttons_layout.add_widget(btn)

        main_layout.add_widget(buttons_layout)

        logout_button = Button(text="Sair", size_hint_y=None, height=50)
        logout_button.bind(on_press=self.go_to_login)
        main_layout.add_widget(logout_button)

        self.add_widget(main_layout)

    def go_to_port_scanner(self, instance):
        print("Navegar para PortScanner")
        self.manager.current = "port_scanner"

    def go_to_whois_lookup(self, instance):
        print("Navegar para Whois LookUp")
        self.manager.current = "whois_lookup"

    def go_to_ip_geolocation(self, instance):
        print("Navegar para IP GeoLocation")
        self.manager.current = "ip_geolocation"

    def go_to_hash_identifier(self, instance):
        print("Navegar para Hash Identifier")
        self.manager.current = "hash_identifier"

    def go_to_ping(self, instance):
        print("Navegar para Ping")
        self.manager.current = "ping"

    def go_to_login(self, instance):
        self.manager.current = "login"
    
    def go_to_sobre(self, instance):
            self.manager.current = "sobre"
            

class SobreScreen(Screen):
	def __init__(self, **kwargs):
		super(SobreScreen, self).__init__(**kwargs)
	
    	
# parte do portscanner
class PortScannerScreen(Screen):
    def __init__(self, **kwargs):
        super(PortScannerScreen, self).__init__(**kwargs)

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)
        self.host_input = TextInput(
            hint_text="Digite o IP", multiline=False, size_hint_y=0.1
        )
        self.result_label = Label(text="Resultado aqui", size_hint_y=0.7)

        scan_button = Button(text="Escanear", size_hint_y=0.1)
        scan_button.bind(on_press=self.iniciar_escaneamento)

        voltar_button = Button(text="Voltar", size_hint_y=0.1)
        voltar_button.bind(on_press=self.voltar_tela)

        layout.add_widget(self.host_input)
        layout.add_widget(scan_button)
        layout.add_widget(self.result_label)
        layout.add_widget(voltar_button)

        self.add_widget(layout)

    def voltar_tela(self, instance):
        self.manager.current = "home"  

    def iniciar_escaneamento(self, instance):
        t = threading.Thread(target=self.scan_ports)
        t.start()

    def scan_ports(self):
        host = self.host_input.text.strip()
        resultado = ""
        portas_comuns = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
        for port in portas_comuns:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    resultado += f"Porta {port} aberta\n"
                sock.close()

            except:
                resultado += f"Erro ao tentar a porta {port}\n"

        Clock.schedule_once(
            lambda dt: setattr(
                self.result_label,
                "text",
                resultado if resultado else "Nenhuma porta aberta encontrada.",
            ),
            0,
        )

    def go_back(self, instance):
        self.manager.current = "home"


class WhoisLookupScreen(Screen):
    def __init__(self, **kwargs):
        super(WhoisLookupScreen, self).__init__(**kwargs)

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)
        layout.add_widget(Label(text="Whois LookUp", font_size="25sp", size_hint_y=None, height=50))

        self.domain_input = TextInput(hint_text="Digite o domínio ou IP", multiline=False, size_hint_y=0.1)
        self.result_label = Label(text="Resultado aqui", size_hint_y=0.7)

        lookup_button = Button(text="Consultar", size_hint_y=0.1)
        lookup_button.bind(on_press=self.do_whois_lookup)

        back_button = Button(text="Voltar", size_hint_y=0.1)
        back_button.bind(on_press=self.go_back)

        layout.add_widget(self.domain_input)
        layout.add_widget(lookup_button)
        layout.add_widget(self.result_label)
        layout.add_widget(back_button)

        self.add_widget(layout)

    def do_whois_lookup(self, instance):
        domain = self.domain_input.text.strip()
        if domain:
            threading.Thread(target=self._perform_whois_lookup, args=(domain,)).start()
        else:
            self.result_label.text = "Por favor, digite um domínio ou IP."

    def _perform_whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            result = str(w)
        except Exception as e:
            result = f"Erro ao consultar Whois: {e}"
        Clock.schedule_once(lambda dt: setattr(self.result_label, "text", result), 0)

    def go_back(self, instance):
        self.manager.current = "home"


class IPGeoLocationScreen(Screen):
    def __init__(self, **kwargs):
        super(IPGeoLocationScreen, self).__init__(**kwargs)

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)
        layout.add_widget(Label(text="IP GeoLocation", font_size="25sp", size_hint_y=None, height=50))

        self.ip_input = TextInput(hint_text="Digite o IP", multiline=False, size_hint_y=0.1)
        self.result_label = Label(text="Resultado aqui", size_hint_y=0.7)

        lookup_button = Button(text="Localizar", size_hint_y=0.1)
        lookup_button.bind(on_press=self.do_ip_geolocation)

        back_button = Button(text="Voltar", size_hint_y=0.1)
        back_button.bind(on_press=self.go_back)

        layout.add_widget(self.ip_input)
        layout.add_widget(lookup_button)
        layout.add_widget(self.result_label)
        layout.add_widget(back_button)

        self.add_widget(layout)

    def do_ip_geolocation(self, instance):
        ip_address = self.ip_input.text.strip()
        if ip_address:
            threading.Thread(target=self._perform_ip_geolocation, args=(ip_address,)).start()
        else:
            self.result_label.text = "Por favor, digite um IP."

    def _perform_ip_geolocation(self, ip_address):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query")
            data = response.json()
            if data["status"] == "success":
                result = (
                    "País: " + str(data.get("country")) + "\n" +
                    "Região: " + str(data.get("regionName")) + "\n" +
                    "Cidade: " + str(data.get("city")) + "\n" +
                    "CEP: " + str(data.get("zip")) + "\n" +
                    "Latitude: " + str(data.get("lat")) + "\n" +
                    "Longitude: " + str(data.get("lon")) + "\n" +
                    "ISP: " + str(data.get("isp")) + "\n" +
                    "Organização: " + str(data.get("org")) + "\n" +
                    "AS: " + str(data.get("as")) + "\n" +
                    "IP: " + str(data.get("query"))
                )
            else:
                result = f"Erro ao localizar IP: {data.get('message', 'Erro desconhecido')}"
        except Exception as e:
            result = f"Erro de conexão: {e}"
        Clock.schedule_once(lambda dt: setattr(self.result_label, "text", result), 0)

    def go_back(self, instance):
        self.manager.current = "home"


class HashIdentifierScreen(Screen):
    def __init__(self, **kwargs):
        super(HashIdentifierScreen, self).__init__(**kwargs)

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)
        layout.add_widget(Label(text="Hash Identifier", font_size="25sp", size_hint_y=None, height=50))

        self.hash_input = TextInput(hint_text="Digite o Hash", multiline=False, size_hint_y=0.1)
        self.result_label = Label(text="Resultado aqui", size_hint_y=0.7)

        identify_button = Button(text="Identificar", size_hint_y=0.1)
        identify_button.bind(on_press=self.do_hash_identify)

        back_button = Button(text="Voltar", size_hint_y=0.1)
        back_button.bind(on_press=self.go_back)

        layout.add_widget(self.hash_input)
        layout.add_widget(identify_button)
        layout.add_widget(self.result_label)
        layout.add_widget(back_button)

        self.add_widget(layout)

    def do_hash_identify(self, instance):
        hash_value = self.hash_input.text.strip()
        if hash_value:
            threading.Thread(target=self._perform_hash_identify, args=(hash_value,)).start()
        else:
            self.result_label.text = "Por favor, digite um hash."

    def _perform_hash_identify(self, hash_value):
        hash_length = len(hash_value)
        hash_type = "Desconhecido"

        if hash_length == 32:
            hash_type = "MD5"
        elif hash_length == 40:
            hash_type = "SHA1"
        elif hash_length == 64:
            hash_type = "SHA256"
        elif hash_length == 96:
            hash_type = "SHA384"
        elif hash_length == 128:
            hash_type = "SHA512"
        elif hash_length == 56:
            hash_type = "SHA224"
        elif hash_length == 16:
            hash_type = "MD4/MD2/NTLM"

        result = f"Hash: {hash_value}\nTipo Identificado: {hash_type}"
        Clock.schedule_once(lambda dt: setattr(self.result_label, "text", result), 0)

    def go_back(self, instance):
        self.manager.current = "home"


class PingScreen(Screen):
    def __init__(self, **kwargs):
        super(PingScreen, self).__init__(**kwargs)

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)
        layout.add_widget(Label(text="Ping", font_size="25sp", size_hint_y=None, height=50))

        self.host_input = TextInput(hint_text="Digite o host ou IP", multiline=False, size_hint_y=0.1)
        self.result_label = Label(text="Resultado aqui", size_hint_y=0.7)

        ping_button = Button(text="Ping", size_hint_y=0.1)
        ping_button.bind(on_press=self.do_ping)

        back_button = Button(text="Voltar", size_hint_y=0.1)
        back_button.bind(on_press=self.go_back)

        layout.add_widget(self.host_input)
        layout.add_widget(ping_button)
        layout.add_widget(self.result_label)
        layout.add_widget(back_button)

        self.add_widget(layout)

    def do_ping(self, instance):
        host = self.host_input.text.strip()
        if host:
            threading.Thread(target=self._perform_ping, args=(host,)).start()
        else:
            self.result_label.text = "Por favor, digite um host ou IP."

    def _perform_ping(self, host):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "4", host]
        try:
            output = subprocess.check_output(command, encoding="utf-8", timeout=10)
            result = output
        except subprocess.CalledProcessError as e:
            result = f"Erro ao executar ping: {e}"
        except subprocess.TimeoutExpired:
            result = "Ping timeout."
        except Exception as e:
            result = f"Erro: {e}"
        Clock.schedule_once(lambda dt: setattr(self.result_label, "text", result), 0)

    def go_back(self, instance):
        self.manager.current = "home"


class PentBoxApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name="login"))
        sm.add_widget(CreateAccountScreen(name="create_account"))
        sm.add_widget(HomeScreen(name="home"))
        sm.add_widget(PortScannerScreen(name="port_scanner"))
        sm.add_widget(WhoisLookupScreen(name="whois_lookup"))
        sm.add_widget(IPGeoLocationScreen(name="ip_geolocation"))
        sm.add_widget(HashIdentifierScreen(name="hash_identifier"))
        sm.add_widget(PingScreen(name="ping"))
        return sm


if __name__ == "__main__":
    PentBoxApp().run()
    
print("debug: chegou até aqui")  # só pra teste