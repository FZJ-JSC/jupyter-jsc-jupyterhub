
import base64
from certipy import Certipy, CertNotFoundError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import datetime
from kubernetes import client, config
import os
import ssl

config.load_incluster_config()
v1 = client.CoreV1Api()
v1custom = client.CustomObjectsApi()
internal_certs_location = "/mnt/persistent/internal-ssl"
secret_name = "internal-ssl"
namespace = os.getenv("HUB_NAMESPACE", "default")
hub_name = os.getenv("HUB_NAME", "jupyterhub")
hub_hostname = os.getenv("HUB_HOSTNAME", "hub")

traefik_proxy_client_secret_name = f"{hub_name}-client-tls"
# traefik_proxy_server_secret_name = f"{hub_name}-server-tls"

recreate_secret = False

def load_secret_and_write_files():
    try:
        secret = v1.read_namespaced_secret(secret_name, namespace)
    except client.exceptions.ApiException as e:
        secret = None
        global recreate_secret
        recreate_secret = True

    os.makedirs(internal_certs_location, exist_ok=True)
    if secret:
        for key, value in secret.data.items():
            if key.endswith("_trust.crt"):
                print(f"Skipping trust file: {key}")
                continue
            if "_" in key:
                base, filename = key.split("_", 1)
            else:
                print(f"Skipping unrecognized file: {key}")
                continue
            # Create subdirectory
            subdir = os.path.join(internal_certs_location, base)
            os.makedirs(subdir, exist_ok=True)
            file_path = os.path.join(subdir, filename)
            decoded = base64.b64decode(value)
            with open(file_path, "wb") as f:
                f.write(decoded)
            print(f"Wrote {file_path}")

def create_secret():
    global recreate_secret
    data = {}
    # Walk through subdirectories (e.g. hub-ca/, notebooks-ca/)
    for root, dirs, files in os.walk(internal_certs_location):
        base = os.path.basename(root)
        for file in files:
            # Construct key name: hub-ca/hub-ca.key -> hub-ca_hub-ca.key
            src_path = os.path.join(root, file)
            if root == internal_certs_location:
                key_name = file
            else:
                key_name = f"{base}_{file}"
            with open(src_path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("utf-8")
            data[key_name] = encoded
            print(f"Added {key_name} from {src_path}")
    secret_body = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name),
        type="Opaque",
        data=data,
    )
    try:
        # Try to delete if it already exists
        v1.read_namespaced_secret(secret_name, namespace)
        if recreate_secret:
            v1.delete_namespaced_secret(secret_name, namespace)
            print(f"Recreate existing secret '{secret_name}' in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            recreate_secret = True
            pass
        else:
            print(f"Error creating/updating secret '{secret_name}': {e}")
            return 1

    try:
        if recreate_secret:
            v1.create_namespaced_secret(namespace, secret_body)
            print(f"Created new secret '{secret_name}' in namespace '{namespace}'.")
        else:
            print(f"No changes detected. Do not recreate secret '{secret_name}'.")
    except client.exceptions.ApiException as e:
        print(f"Error creating secret '{secret_name}': {e}")
        return 1

    try:
        v1.read_namespaced_secret(traefik_proxy_client_secret_name, namespace)
        if recreate_secret:
            v1.delete_namespaced_secret(traefik_proxy_client_secret_name, namespace)
            print(f"Recreate existing secret '{traefik_proxy_client_secret_name}' in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            recreate_secret = True
            pass
        else:
            print(f"Error creating/updating secret '{namespace}:{traefik_proxy_client_secret_name}': {e}")
    try:
        if recreate_secret:
            traefik_data = {}
            traefik_data["ca.crt"] = data["proxy-client-ca_trust.crt"]
            traefik_data["tls.crt"] = data["proxy-client_proxy-client.crt"]
            traefik_data["tls.key"] = data["proxy-client_proxy-client.key"]
            traefik_secret_body = client.V1Secret(
                metadata=client.V1ObjectMeta(name=traefik_proxy_client_secret_name),
                type="Opaque",
                data=traefik_data,
            )
            v1.create_namespaced_secret(namespace, traefik_secret_body)
            print(f"Created new secret '{traefik_proxy_client_secret_name}' in namespace '{namespace}'.")
    except client.exceptions.ApiException as e:
        print(f"Error creating secret '{namespace}:{traefik_proxy_client_secret_name}': {e}")
        return 1


external_ssl_authorities = {
    "hub-ca": {
        "key": f"{internal_certs_location}/hub-ca/hub-ca.key",
        "cert": f"{internal_certs_location}/hub-ca/hub-ca.crt",
        "ca": f"{internal_certs_location}/hub-ca_trust.crt",
    },
    "notebooks-ca": {
        "key": f"{internal_certs_location}/notebooks-ca/notebooks-ca.key",
        "cert": f"{internal_certs_location}/notebooks-ca/notebooks-ca.crt",
        "ca": f"{internal_certs_location}/notebooks-ca_trust.crt",
    },
    "proxy-api-ca": {
        "key": f"{internal_certs_location}/proxy-api-ca/proxy-api-ca.key",
        "cert": f"{internal_certs_location}/proxy-api-ca/proxy-api-ca.crt",
        "ca": f"{internal_certs_location}/proxy-api-ca_trust.crt",
    },
    "proxy-client-ca": {
        "key": f"{internal_certs_location}/proxy-client-ca/proxy-client-ca.key",
        "cert": f"{internal_certs_location}/proxy-client-ca/proxy-client-ca.crt",
        "ca": f"{internal_certs_location}/proxy-client-ca_trust.crt",
    },
    "services-ca": {
        "key": f"{internal_certs_location}/services-ca/services-ca.key",
        "cert": f"{internal_certs_location}/services-ca/services-ca.crt",
        "ca": f"{internal_certs_location}/services-ca_trust.crt",
    },
}

internal_ssl_authorities = {
    "hub-ca": None,
    "notebooks-ca": None,
    "proxy-api-ca": None,
    "proxy-client-ca": None,
    "services-ca": None,
}

def load_certificate(cert_path: Path):
    """Load an X.509 certificate from a file."""
    print(f"Loading certificate from {cert_path}")
    with open(cert_path, "rb") as f:
        data = f.read()
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except ValueError:
            try:
                return x509.load_der_x509_certificate(data, default_backend())
            except Exception as e:
                print(f"Error loading certificate from {cert_path}: {e}")
                return None
        except Exception as e:
            print(f"Error loading certificate from {cert_path}: {e}")
            return None

def certificate_expires_within(cert: x509.Certificate, days: int = 7) -> bool:
    """Check if the certificate expires within the next 'days' days."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = cert.not_valid_after_utc
    delta = expires - now
    return delta <= datetime.timedelta(days=days)

def verify_cert_key_match(cert_path: Path, key_path: Path) -> bool:
    """Verify if the private key matches the certificate."""
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return True
    except ssl.SSLError:
        return False

def setup_internal_ssl():
    global recreate_secret
    load_secret_and_write_files()
    for component, files in external_ssl_authorities.items():
        cert_path = Path(files["cert"])
        key_path = Path(files["key"])
        ca_path = Path(files["ca"]) if files.get("ca", None) else None
        if cert_path.exists() and key_path.exists():
            cert = load_certificate(cert_path)
            if cert and certificate_expires_within(cert, days=30):
                print(
                    f"Warning: The certificate for {component} expires soon on {cert.not_valid_after}."
                )
            if not verify_cert_key_match(cert_path, key_path):
                print(f"Error: The certificate and key for {component} do not match.")
                recreate_secret = True
            else:
                internal_ssl_authorities[component] = {
                    "key": str(key_path),
                    "cert": str(cert_path),
                    "ca": str(ca_path) if ca_path else None,
                }
        else:
            print(
                f"Info: Certificate or key file for {component} does not exist. Using default internal SSL setup."
            )
            recreate_secret = True
    certipy = Certipy(
        store_dir=internal_certs_location,
        remove_existing=False,
    )
    internal_ssl_components_trust = {
        "hub-ca": list(internal_ssl_authorities.keys()),
        "proxy-api-ca": ["hub-ca", "services-ca", "notebooks-ca"],
        "proxy-client-ca": ["hub-ca", "notebooks-ca"],
        "notebooks-ca": ["hub-ca", "proxy-client-ca"],
        "services-ca": ["hub-ca", "proxy-api-ca"],
    }
    # If any external CAs were specified in external_ssl_authorities
    # add records of them to Certipy's store.
    for authority, files in internal_ssl_authorities.items():
        if files:
            certipy.store.add_record(authority, is_ca=True, files=files, overwrite=True)
    certipy.trust_from_graph(internal_ssl_components_trust)
    alt_names = [
        "IP:127.0.0.1",
        "IP:0:0:0:0:0:0:0:1",
        "DNS:localhost",
        f"DNS:hub.{namespace}.svc",
        "DNS:hub",
        f"DNS:{hub_hostname}"
    ]
    component_ca = {
        "proxy-api": "proxy-api-ca",
        "proxy-client": "proxy-client-ca",
        "hub-internal": "hub-ca",
    }
    for component, ca_name in component_ca.items():
        try:
            certipy.store.get_record(component)
        except CertNotFoundError:
            print(
                f"Generating signed pair for {component}: {';'.join(alt_names)}"
            )
            certipy.create_signed_pair(
                component, ca_name, alt_names=alt_names
            )
        else:
            print(f"Using existing {component} CA")
    create_secret()
setup_internal_ssl()