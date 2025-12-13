import binascii
import importlib.util
import sys

from scapy.all import IP, TCP, sniff, conf

if importlib.util.find_spec("scapy") is None:
    print("El módulo 'scapy' no está instalado. Instálalo con 'pip install scapy'.")
    sys.exit(1)

# Definición de tamaños para header y footer (ajusta según tu protocolo)
HEADER_SIZE = 2  # Primeros 2 bytes como header
FOOTER_SIZE = 8  # Últimos 8 bytes como footer

# Lista de claves XOR para probar
XOR_KEYS = [0x00, 0xED]  

def xor_decrypt(data, key):
    """Desencripta datos utilizando XOR con la clave proporcionada."""
    return bytearray(byte ^ key for byte in data)

def format_payload(payload):
    """Convierte el payload en formato [0x00, 0x01, ...]."""
    return "[" + ", ".join(f"0x{byte:02X}" for byte in payload) + "]"

def format_ascii(payload):
    """Convierte el payload a su representación ASCII, con '.' para caracteres no imprimibles."""
    return ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in payload)

def analyze_packet(packet):
    """Analiza el paquete y muestra sus detalles utilizando varias claves XOR."""
    payload = bytes(packet[TCP].payload.load)  # Extrae los bytes del payload

    print("=" * 50)
    print(f"Source: {packet[IP].src}:{packet[TCP].sport}")
    print(f"Destination: {packet[IP].dst}:{packet[TCP].dport}")
    print(f"Payload Length: {len(payload)} bytes")

    for key in XOR_KEYS:
        decrypted_payload = xor_decrypt(payload, key)  # Desencripta con la clave XOR

        # Extraer header, contenido y footer
        header = decrypted_payload[:HEADER_SIZE]
        footer = decrypted_payload[-FOOTER_SIZE:] if len(decrypted_payload) > FOOTER_SIZE else b""
        content = decrypted_payload[HEADER_SIZE:-FOOTER_SIZE] if len(decrypted_payload) > HEADER_SIZE + FOOTER_SIZE else b""

        print(f"\n--- Resultado con XOR Key: 0x{key:02X} ---")
        print(f"Header (Hex): {format_payload(header)}")
        print(f"Content (Hex): {format_payload(content)}")
        print(f"Footer (Hex): {format_payload(footer)}")
        print(f"Content (ASCII): {format_ascii(content)}")

    print("=" * 50)

def packet_handler(packet):
    """Manejador de paquetes capturados."""
    if (
        packet.haslayer(TCP)
        and (packet[TCP].sport == 11000 or packet[TCP].dport == 11000)
        and packet[TCP].payload
    ):
        analyze_packet(packet)

def start_sniffer():
    """Inicia el sniffer apuntando a todas las interfaces disponibles."""
    print("Iniciando el sniffer en 0.0.0.0:11000...")
    try:
        sniff(
            prn=packet_handler,
            filter="tcp port 11000",
            store=0
        )
    except KeyboardInterrupt:
        print("\nSniffer detenido por el usuario.")
    except Exception as e:
        print(
            "Error al iniciar el sniffer con libpcap/winpcap: "
            f"{e}. Intentando modo de compatibilidad en capa 3..."
        )
        try:
            sniff(prn=packet_handler, store=0, opened_socket=conf.L3socket())
        except Exception as fallback_error:
            print(
                "El sniffer no pudo iniciarse en modo de compatibilidad. "
                "Asegúrate de tener WinPcap/Npcap instalado o ejecuta con permisos de administrador."
            )
            print(f"Detalle del error: {fallback_error}")

if __name__ == "__main__":
    start_sniffer()
