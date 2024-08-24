import requests
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
import tempfile
import os
import ssl
from requests.adapters import HTTPAdapter

class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)

# Path to the cert.pfx file in your project directory
CERT_PATH = 'cert.pfx'  # Assuming cert.pfx is at the root of your GitHub project
CERT_PASSWORD = 'sape'  # Your actual password

# SOAP service URLs and request bodies
SOAP_SERVICES = {
    'padres': 'https://renaperdatosc.idear.gov.ar:8446/WSpadres.php',
    'hijos': 'https://renaperdatosc.idear.gov.ar:8446/WShijos.php',
    'fiscal': 'https://renaperdatosc.idear.gov.ar:8446/DATOSCMPFISCAL.php'
}

SOAP_BODIES = {
    'padres': '''<x:Envelope
        xmlns:x="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:urn="urn:padreswsdl">
        <x:Header/>
        <x:Body>
            <urn:obtenerDatosPadres>
                <urn:DatosEntrada>
                    <dni>{{dni}}</dni>
                    <sexo>{{sexo}}</sexo>
                </urn:DatosEntrada>
            </urn:obtenerDatosPadres>
        </x:Body>
    </x:Envelope>''',
    'hijos': '''<x:Envelope
        xmlns:x="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:urn="urn:hijoswsdl">
        <x:Header/>
        <x:Body>
            <urn:obtenerDatosHijos>
                <urn:DatosEntrada>
                    <dni>{{dni}}</dni>
                    <sexo>{{sexo}}</sexo>
                </urn:DatosEntrada>
            </urn:obtenerDatosHijos>
        </x:Body>
    </x:Envelope>''',
    'fiscal': '''<x:Envelope
        xmlns:x="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:urn1="urn:miniteriorwsdl"
        xmlns:urn="urn:mininteriorwsdl">
        <x:Header/>
        <x:Body>
            <urn1:obtenerUltimoEjemplar>
                <urn1:DatosEntrada>
                    <urn:dni>{{dni}}</urn:dni>
                    <urn:sexo>{{sexo}}</urn:sexo>
                </urn1:DatosEntrada>
            </urn1:obtenerUltimoEjemplar>
        </x:Body>
    </x:Envelope>'''
}

def get_cert(cert_path, password):
    with open(cert_path, 'rb') as f:
        p12_data = f.read()
    
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        p12_data,
        password.encode(),
        backend=None
    )
    
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')

    cert_file.write(cert_pem)
    cert_file.close()

    key_file.write(key_pem)
    key_file.close()

    return (cert_file.name, key_file.name)

def make_soap_request(service_name, dni, sexo):
    url = SOAP_SERVICES[service_name]
    body = SOAP_BODIES[service_name].format(dni=dni, sexo=sexo)
    
    cert_path, key_path = get_cert(CERT_PATH, CERT_PASSWORD)
    
    # Create SSL context to allow weaker ciphers and adjust security level
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers('DEFAULT:@SECLEVEL=0')
    context.check_hostname = False  # Disable hostname check
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    
    # Adapter for requests with custom SSL
    session = requests.Session()
    adapter = SSLAdapter(ssl_context=context)
    session.mount("https://", adapter)
    
    try:
        response = session.post(
            url,
            data=body,
            headers={
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': f"urn:{service_name}wsdl#obtenerDatos{service_name.capitalize()}"
            },
            cert=(cert_path, key_path),
            verify=False  
        )
    finally:
        os.remove(cert_path)
        os.remove(key_path)

    return response.text

def fetch_data(dni, sexo):
    results = {}
    for service in ['padres', 'hijos']:
        results[service] = make_soap_request(service, dni, sexo)
    # Include the new fiscal query
    results['fiscal'] = make_soap_request('fiscal', dni, sexo)
    return results

# Test the function with example data
print(fetch_data(49666519, "M"))
