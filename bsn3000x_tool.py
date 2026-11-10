#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TP-Link Aginet BSN3000X / EX511 v2 - Backup Configuration Tool
==============================================================
Utilitário para Descriptografar, Desbloquear (Admin Telnet e Desativação do TR-069)
e Re-criptografar arquivos de backup `conf.bin` de roteadores TP-Link Aginet BSN3000X v1.0.

Baseado na engenharia reversa do ecossistema TP-Link e no algoritmo de
compressão/descompressão do projeto `tpconf_bin_xml` de Alain Ducharme.

A chave DES utilizada pelo modelo BSN3000X v1.0 está catalogada pela comunidade no
repositório upstream: https://github.com/sta-c0000/tpconf_bin_xml (perfil 'bsn3000x-v1').

Licença: GNU General Public License v3.0 (GPL-3.0)
"""

import sys
import os
import re
import argparse
from hashlib import md5
from struct import pack, pack_into, unpack_from

try:
    from Cryptodome.Cipher import DES
except ImportError:
    try:
        from Crypto.Cipher import DES
    except ImportError:
        print("[ERRO] Biblioteca criptográfica não encontrada. Instale com: pip install pycryptodome", file=sys.stderr)
        sys.exit(1)

# Formato Little-Endian para processadores ARM64 (Qualcomm IPQ5018 / BSN3000X)
PACK_INT = '<I'


def parse_des_key(key_input: str) -> bytes:
    """Valida e converte a chave informada para 8 bytes DES."""
    if not key_input:
        raise ValueError("Chave vazia.")
    cleaned = key_input.strip().replace(" ", "").replace("0x", "").replace(",", "")
    if len(cleaned) == 16:
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    if len(key_input) == 8:
        return key_input.encode('latin1')
    try:
        b = bytes.fromhex(cleaned)
        if len(b) == 8:
            return b
    except ValueError:
        pass
    raise ValueError("A chave DES deve conter exatamente 8 bytes (16 caracteres hexadecimais, ex: '0123456789ABCDEF').")


def resolve_key(cli_key: str | None) -> bytes:
    """Obtém a chave via CLI, variável de ambiente ou prompt interativo."""
    if cli_key:
        return parse_des_key(cli_key)
    env_key = os.environ.get("TPCONF_KEY")
    if env_key:
        return parse_des_key(env_key)
    if sys.stdin.isatty():
        print("[*] Chave não informada via CLI (--key) ou variável TPCONF_KEY.")
        print("[*] Consulte as chaves por modelo em: https://github.com/sta-c0000/tpconf_bin_xml")
        try:
            user_input = input("[?] Digite a chave DES (hexadecimal de 16 caracteres): ").strip()
            return parse_des_key(user_input)
        except (KeyboardInterrupt, EOFError):
            print("\nOperação cancelada.", file=sys.stderr)
            sys.exit(1)
    print("[ERRO] Chave DES não fornecida. Use o parâmetro --key <HEX>, configure a variável de ambiente TPCONF_KEY ou consulte https://github.com/sta-c0000/tpconf_bin_xml", file=sys.stderr)
    sys.exit(1)


# ==============================================================================
# Algoritmo de Compressão e Descompressão Proprietário TP-Link (LZ / LDB)
# ==============================================================================

def compress(src: bytes, skiphits: bool = True) -> tuple[int, bytearray]:
    """Comprime o conteúdo XML usando o algoritmo de janela LZ proprietário da TP-Link."""
    if src[-1]:
        src += b'\0'
    size = len(src)
    buffer_countdown = size
    hash_table = [0] * 0x2000
    dst = bytearray(max(0x8000, size))
    block16_countdown = 0x10
    block16_dict_bits = 0

    def put_bit(bit: int):
        nonlocal block16_countdown, block16_dict_bits, d_p, d_pb
        if block16_countdown:
            block16_countdown -= 1
        else:
            pack_into('H', dst, d_pb, block16_dict_bits)
            d_pb = d_p
            d_p += 2
            block16_countdown = 0xF
        block16_dict_bits = (bit + (block16_dict_bits << 1)) & 0xFFFF

    def put_dict_ld(bits: int):
        ldb = bits >> 1
        while True:
            lb = (ldb - 1) & ldb
            if not lb:
                break
            ldb = lb
        put_bit(int(ldb & bits > 0))
        ldb = ldb >> 1
        while ldb:
            put_bit(1)
            put_bit(int(ldb & bits > 0))
            ldb = ldb >> 1
        put_bit(0)

    def hash_key(offset: int) -> int:
        b4 = src[offset:offset + 4]
        hk = 0
        for b in b4[:3]:
            hk = (hk + b) * 0x13D
        return (hk + b4[3]) & 0x1FFF

    pack_into(PACK_INT, dst, 0, size)
    dst[4] = src[0]
    buffer_countdown -= 1
    s_p = 1
    s_ph = 0
    d_pb = 5
    d_p = 7

    while buffer_countdown > 4:
        while s_ph < s_p:
            hash_table[hash_key(s_ph)] = s_ph
            s_ph += 1

        match_found = False
        longest_match = 0
        match_p = hash_table[hash_key(s_p)]

        if match_p:
            while match_p and not match_found:
                if (s_p - match_p) <= 0x1FFF:
                    m = 0
                    while (s_p + m) < size and src[s_p + m] == src[match_p + m]:
                        m += 1
                        if m == 0xFF:
                            break
                    if m > longest_match:
                        longest_match = m
                        best_match_p = match_p
                        if longest_match > 4 and skiphits:
                            match_found = True
                match_p = hash_table[hash_key(match_p)]

            if longest_match > 1:
                put_bit(1)
                match_distance = s_p - best_match_p - 1
                ms_b = match_distance >> 5
                ls_b = match_distance & 0x1F
                put_dict_ld(ms_b)
                for i in range(5):
                    put_bit(int(ls_b & (1 << (4 - i)) > 0))
                put_dict_ld(longest_match - 2)
                buffer_countdown -= longest_match
                s_p += longest_match
                continue

        put_bit(0)
        dst[d_p] = src[s_p]
        d_p += 1
        buffer_countdown -= 1
        s_p += 1

    while buffer_countdown:
        put_bit(0)
        dst[d_p] = src[s_p]
        d_p += 1
        buffer_countdown -= 1
        s_p += 1

    block16_dict_bits <<= block16_countdown
    pack_into('H', dst, d_pb, block16_dict_bits)
    return d_p, dst


def uncompress(src: bytes) -> bytes:
    """Descomprime o payload LZ proprietário da TP-Link."""
    orig_size = unpack_from(PACK_INT, src, 0)[0]
    dst = bytearray(orig_size)
    s_p = 4
    d_p = 0
    block16_countdown = 0
    block16_dict_bits = 0

    def get_bit() -> int:
        nonlocal block16_countdown, block16_dict_bits, s_p
        if not block16_countdown:
            block16_dict_bits = unpack_from('H', src, s_p)[0]
            s_p += 2
            block16_countdown = 0x10
        bit = (block16_dict_bits >> 15) & 1
        block16_dict_bits = (block16_dict_bits << 1) & 0xFFFF
        block16_countdown -= 1
        return bit

    def get_dict_ld() -> int:
        cnt = 1
        while get_bit():
            cnt += 1
        val = 0
        for _ in range(cnt):
            val = (val << 1) | get_bit()
        return val

    dst[0] = src[s_p]
    s_p += 1
    d_p += 1

    while d_p < orig_size and s_p < len(src):
        if get_bit():
            ms_b = get_dict_ld() << 5
            ls_b = 0
            for _ in range(5):
                ls_b = (ls_b << 1) | get_bit()
            num_chars = get_dict_ld() + 2
            offset = d_p - (ls_b + 1 + ms_b)
            for _ in range(num_chars):
                dst[d_p] = dst[offset]
                d_p += 1
                offset += 1
        else:
            dst[d_p] = src[s_p]
            s_p += 1
            d_p += 1

    return bytes(dst)


# ==============================================================================
# Operações de Decodificação e Criptografia
# ==============================================================================

def decrypt_conf_bin(input_path: str, key: bytes) -> str:
    """Lê um arquivo conf.bin, valida MD5 e retorna o XML original."""
    with open(input_path, 'rb') as f:
        bin_data = f.read()

    if len(bin_data) % 8 != 0:
        raise ValueError("Tamanho do arquivo binário inválido (deve ser múltiplo de 8).")

    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(bin_data)

    file_hash = decrypted[:16]
    payload = decrypted[16:]

    # Validação do Checksum MD5 (removendo até 8 bytes de padding DES se necessário)
    matched_payload = None
    for pad in range(9):
        test_payload = payload[:len(payload) - pad] if pad else payload
        if md5(test_payload).digest() == file_hash:
            matched_payload = test_payload
            break

    if matched_payload is None:
        raise ValueError("Checksum MD5 inválido. Arquivo corrompido ou chave incorreta!")

    decompressed = uncompress(matched_payload)
    if decompressed.endswith(b'\x00'):
        decompressed = decompressed[:-1]

    return decompressed.decode('utf-8', errors='ignore')


def encrypt_conf_xml(xml_content: str, output_path: str, key: bytes):
    """Comprime o XML, gera o hash MD5 e criptografa com a chave DES."""
    xml_bytes = xml_content.encode('utf-8')
    comp_size, comp_buffer = compress(xml_bytes, skiphits=True)
    payload = bytes(comp_buffer[:comp_size])

    file_hash = md5(payload).digest()
    data = bytearray(file_hash + payload)

    # Padding de zeros até múltiplo de 8 (requisito do DES em blocos)
    if len(data) % 8 != 0:
        data += b'\0' * (8 - (len(data) % 8))

    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_bin = cipher.encrypt(bytes(data))

    # Teste de integridade pré-gravação
    verify_cipher = DES.new(key, DES.MODE_ECB)
    dec_test = verify_cipher.decrypt(encrypted_bin)
    assert md5(dec_test[16:16 + comp_size]).digest() == dec_test[:16], "Falha no hash MD5 do arquivo gerado!"

    with open(output_path, 'wb') as f:
        f.write(encrypted_bin)


def unlock_xml(xml_content: str, new_password: str = "ednan2106") -> str:
    """
    Aplica as alterações cirúrgicas para liberar acesso Admin/Telnet e desativar TR-069
    sem modificar nenhuma flag de restrição ou interface web (preservando o layout original).
    """
    # 1. Habilita AdminEnable
    xml = xml_content.replace('<AdminEnable val=0 />', '<AdminEnable val=1 />')

    # 2. Habilita a conta de Usuário instance=1 (admin)
    old_admin_block = """      <User instance=1 >
        <RemoteAccessCapable val=1 />
        <Username val=admin />
        <Password val=admin />
      </User>"""

    new_admin_block = f"""      <User instance=1 >
        <Enable val=1 />
        <RemoteAccessCapable val=1 />
        <Username val=admin />
        <Password val={new_password} />
      </User>"""

    if old_admin_block in xml:
        xml = xml.replace(old_admin_block, new_admin_block)
    else:
        # Regex defensivo caso espaçamento varie
        xml = re.sub(
            r'<User instance=1 >\s*<RemoteAccessCapable val=1 />\s*<Username val=admin />\s*<Password val=[^/]+ />\s*</User>',
            f'<User instance=1 >\n        <Enable val=1 />\n        <RemoteAccessCapable val=1 />\n        <Username val=admin />\n        <Password val={new_password} />\n      </User>',
            xml
        )

    # 3. Neutraliza o servidor TR-069 (CWMP) remoto da operadora / ISP
    # Redireciona a URL do servidor ACS para localhost (captura qualquer URL/domínio)
    xml = re.sub(
        r'<URL val=https?://\S+\s*/>',
        '<URL val=http://127.0.0.1:7547/disabled />',
        xml,
        count=1
    )
    # Neutraliza ConnectionRequestURL para qualquer host/IP
    xml = re.sub(
        r'<ConnectionRequestURL val=https?://\S+\s*/>',
        '<ConnectionRequestURL val=http://127.0.0.1:7547/disabled />',
        xml
    )
    # Define intervalo de informe astronômico (~3 anos)
    xml = re.sub(
        r'<PeriodicInformInterval val=\d+\s*/>',
        '<PeriodicInformInterval val=99999999 />',
        xml
    )

    return xml


# ==============================================================================
# Interface CLI
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="TP-Link Aginet BSN3000X / EX511 Backup Config Tool"
    )
    parser.add_argument(
        "--key", "-k",
        help="Chave DES (16 caracteres hexadecimais). Pode também ser definida via env var TPCONF_KEY. Se omitida, será solicitada no terminal."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando decrypt
    p_dec = subparsers.add_parser("decrypt", help="Descriptografa conf.bin e salva como conf.xml")
    p_dec.add_argument("input", help="Arquivo conf.bin de entrada")
    p_dec.add_argument("output", help="Arquivo conf.xml de saída")

    # Subcomando encrypt
    p_enc = subparsers.add_parser("encrypt", help="Comprime e criptografa conf.xml em conf.bin")
    p_enc.add_argument("input", help="Arquivo conf.xml de entrada")
    p_enc.add_argument("output", help="Arquivo conf.bin de saída")

    # Subcomando unlock
    p_unl = subparsers.add_parser("unlock", help="Desbloqueia Admin e neutraliza TR-069 diretamente")
    p_unl.add_argument("input", help="Arquivo conf.bin original")
    p_unl.add_argument("output", help="Arquivo conf_unlocked.bin pronto para restauração")
    p_unl.add_argument("--password", default="ednan2106", help="Nova senha para a conta admin (padrão: ednan2106)")

    args = parser.parse_args()
    key = resolve_key(args.key)

    if args.command == "decrypt":
        print(f"[*] Descriptografando {args.input}...")
        xml_text = decrypt_conf_bin(args.input, key)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(xml_text)
        print(f"[+] Sucesso! XML gerado em: {args.output} ({len(xml_text)} caracteres).")

    elif args.command == "encrypt":
        print(f"[*] Lendo {args.input}...")
        with open(args.input, 'r', encoding='utf-8') as f:
            xml_text = f.read()
        print(f"[*] Comprimindo e criptografando para {args.output}...")
        encrypt_conf_xml(xml_text, args.output, key)
        print(f"[+] Sucesso! Arquivo criptografado gerado em: {args.output}.")

    elif args.command == "unlock":
        print(f"[*] Lendo e descriptografando backup original: {args.input}...")
        xml_text = decrypt_conf_bin(args.input, key)
        print("[*] Aplicando alterações cirúrgicas:")
        print("    - Ativando flag AdminEnable (<AdminEnable val=1 />)")
        print(f"    - Habilitando conta admin (User instance=1) com senha: {args.password}")
        print("    - Neutralizando servidor TR-069 (CWMP) da operadora/ISP (redirecionado para 127.0.0.1)")
        print("    - Preservando integralmente as flags de visualização da interface web")
        unlocked_xml = unlock_xml(xml_text, args.password)
        print(f"[*] Criptografando backup desbloqueado para: {args.output}...")
        encrypt_conf_xml(unlocked_xml, args.output, key)
        print(f"[+] Sucesso total! O arquivo {args.output} foi gerado e pode ser restaurado no roteador.")


if __name__ == '__main__':
    main()
