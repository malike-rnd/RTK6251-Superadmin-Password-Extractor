#!/usr/bin/env python3
"""
RTK6251 Superadmin Password Extractor
======================================
Извлечение пароля суперадминистратора из PON-розетки Rotek RTK6251 (Ростелеком).

Также может работать на клоне Transservice TS-1001GF и других терминалах
на базе Realtek RTL9603 с аналогичной прошивкой.

Требуется: pip install requests

Использование:
    python rtk6251_superadmin.py -L admin -P <пароль_с_наклейки>
    python rtk6251_superadmin.py -L admin -P <пароль> -H 192.168.0.1
    python rtk6251_superadmin.py --file config.xml

Автор идеи дешифровки: malike + zl0i + сообщество
На основе анализа формата конфигурации RTK6251.
"""

import argparse
import sys
import os

try:
    import requests
except ImportError:
    print("[!] Требуется библиотека requests: pip install requests")
    sys.exit(1)

from hashlib import md5
from random import random

# ============================================================
# Константы
# ============================================================

XOR_KEY = b"tecomtec"  # 8-байтовый XOR-ключ шифрования конфига

# ============================================================
# Функции дешифровки
# ============================================================

def xor_decrypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """XOR-дешифровка конфигурационного файла."""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def decode_credential(obfuscated: str) -> str:
    """
    Декодирование обфусцированных учётных данных из конфига.
    Алгоритм: реверс строки + сдвиг каждого символа на -1 (Caesar -1).
    
    Пример:
        ojnebsfqvt → (каждый символ -1) → nimdarepus → (реверс) → superadmin
    """
    shifted = "".join(chr(ord(c) - 1) for c in obfuscated)
    return shifted[::-1]


def encode_credential(plaintext: str) -> str:
    """
    Обратная операция — кодирование (для проверки).
    Алгоритм: реверс строки + сдвиг каждого символа на +1 (Caesar +1).
    """
    reversed_text = plaintext[::-1]
    return "".join(chr(ord(c) + 1) for c in reversed_text)

# ============================================================
# Работа с роутером
# ============================================================

def router_login(host: str, login: str, password: str) -> requests.Session:
    """Авторизация на роутере, возвращает сессию."""
    url = f"http://{host}"
    session = requests.Session()
    session.post(
        f"{url}/login.htm",
        data={
            "f_password": md5(password.encode()).hexdigest(),
            "f_currURL": f"{url}/old_login.htm",
            "f_username": login,
            "pwd": "",
        },
        timeout=10,
    )
    return session


def get_session_key(session: requests.Session, host: str) -> str:
    """Получение ключа сессии для доступа к конфигу."""
    url = f"http://{host}"
    resp = session.get(
        f"{url}/advanced/conSession.htm",
        params={"id": str(random())},
        timeout=10,
    )
    return resp.text.strip()


def download_config(session: requests.Session, host: str) -> bytes:
    """Скачивание зашифрованного конфигурационного файла."""
    url = f"http://{host}"
    session_key = get_session_key(session, host)
    resp = session.get(
        f"{url}/config_old_tl.xgi",
        params={"sessionKey": session_key},
        timeout=30,
    )
    if len(resp.content) < 100:
        raise RuntimeError(
            f"Получен слишком маленький ответ ({len(resp.content)} байт). "
            "Проверьте логин/пароль или попробуйте скачать конфиг вручную."
        )
    return resp.content

# ============================================================
# Парсинг конфига
# ============================================================

def parse_credentials(xml_text: str) -> dict:
    """Извлечение всех учётных данных из расшифрованного конфига."""
    creds = {}

    # Ищем пары Name/Value
    import re
    pattern = re.compile(r'Name="([^"]+)"\s+Value="([^"]*)"')

    fields_of_interest = {
        "USER_NAME":              "admin_login",
        "USER_PASSWORD":          "admin_password",
        "SUSER_NAME":             "superadmin_login",
        "SUSER_PASSWORD":         "superadmin_password",
        "CWMP_ACS_USERNAME":      "cwmp_acs_login",
        "CWMP_ACS_PASSWORD":      "cwmp_acs_password",
        "CWMP_CONREQ_USERNAME":   "cwmp_conreq_login",
        "CWMP_CONREQ_PASSWORD":   "cwmp_conreq_password",
        "GPON_PLOAM_PASSWD":      "gpon_ploam_password",
        "LOID_PASSWD":            "loid_password",
    }

    # PPPoE может встречаться несколько раз — берём первый непустой
    ppp_user = None
    ppp_pass = None

    for match in pattern.finditer(xml_text):
        name, value = match.group(1), match.group(2)

        if name in fields_of_interest and value:
            creds[fields_of_interest[name]] = value

        if name == "pppUser" and value and not ppp_user:
            ppp_user = value
        if name == "pppPasswd" and value and not ppp_pass:
            ppp_pass = value

    if ppp_user:
        creds["pppoe_login"] = ppp_user
    if ppp_pass:
        creds["pppoe_password"] = ppp_pass

    return creds

# ============================================================
# Вывод результатов
# ============================================================

def print_results(creds: dict):
    """Красивый вывод найденных учётных данных."""

    sep = "=" * 60
    print(f"\n{sep}")
    print("  RTK6251 — Извлечённые учётные данные")
    print(sep)

    # Суперадмин
    if "superadmin_login" in creds:
        raw_login = creds["superadmin_login"]
        raw_pass = creds.get("superadmin_password", "")
        dec_login = decode_credential(raw_login)
        dec_pass = decode_credential(raw_pass)

        print(f"\n  ★ СУПЕРАДМИН")
        print(f"    Логин:    {dec_login}")
        print(f"    Пароль:   {dec_pass}")
        print(f"    (в конфиге: {raw_login} / {raw_pass})")

    # Обычный админ
    if "admin_login" in creds:
        raw_login = creds["admin_login"]
        raw_pass = creds.get("admin_password", "")
        dec_login = decode_credential(raw_login)
        dec_pass = decode_credential(raw_pass)

        print(f"\n  ◆ АДМИН (user)")
        print(f"    Логин:    {dec_login}")
        print(f"    Пароль:   {dec_pass}")
        print(f"    (в конфиге: {raw_login} / {raw_pass})")

    # PPPoE (хранится без обфускации — как есть)
    if "pppoe_login" in creds:
        print(f"\n  ◆ PPPoE (подключение к интернету)")
        print(f"    Логин:    {creds['pppoe_login']}")
        print(f"    Пароль:   {creds.get('pppoe_password', '')}")

    # CWMP / TR-069
    if "cwmp_acs_login" in creds:
        print(f"\n  ◇ TR-069 (CWMP ACS)")
        print(f"    Логин:    {creds['cwmp_acs_login']}")
        print(f"    Пароль:   {creds.get('cwmp_acs_password', '')}")

    if "cwmp_conreq_login" in creds:
        print(f"\n  ◇ TR-069 (Connection Request)")
        print(f"    Логин:    {creds['cwmp_conreq_login']}")
        print(f"    Пароль:   {creds.get('cwmp_conreq_password', '')}")

    print(f"\n{sep}")
    print("  Для входа в веб-интерфейс: http://192.168.0.1")
    print("  Используйте логин/пароль суперадмина для полного доступа.")
    print(f"{sep}\n")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Rotek RTK6251 — извлечение пароля суперадминистратора",
        epilog="Примеры:\n"
               "  %(prog)s -L admin -P пароль_с_наклейки\n"
               "  %(prog)s -L admin -P пароль_с_наклейки -H 192.168.0.1\n"
               "  %(prog)s --file config.xml\n"
               "  %(prog)s --file config.xml --save\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-H", "--host", type=str, default="192.168.0.1",
                        help="IP-адрес роутера (по умолчанию 192.168.0.1)")
    parser.add_argument("-L", "--login", type=str,
                        help="логин администратора (обычно admin)")
    parser.add_argument("-P", "--password", type=str,
                        help="пароль администратора (с наклейки на корпусе)")
    parser.add_argument("-f", "--file", type=str,
                        help="путь к уже скачанному конфигу (config.xml / config.bin)")
    parser.add_argument("-s", "--save", action="store_true",
                        help="сохранить расшифрованный конфиг в файл")

    args = parser.parse_args()

    # Проверка аргументов
    if not args.file and (not args.login or not args.password):
        parser.error("Укажите --login и --password для скачивания с роутера, "
                      "либо --file для работы с уже скачанным конфигом.")

    # Получение зашифрованного конфига
    if args.file:
        print(f"[*] Чтение конфига из файла: {args.file}")
        with open(args.file, "rb") as f:
            encrypted = f.read()
        print(f"[*] Размер файла: {len(encrypted)} байт")
    else:
        print(f"[*] Подключение к {args.host}...")
        try:
            session = router_login(args.host, args.login, args.password)
            print(f"[+] Авторизация успешна")
        except Exception as e:
            print(f"[!] Ошибка авторизации: {e}")
            sys.exit(1)

        print(f"[*] Скачивание конфигурации...")
        try:
            encrypted = download_config(session, args.host)
            print(f"[+] Конфиг получен: {len(encrypted)} байт")
        except Exception as e:
            print(f"[!] Ошибка скачивания: {e}")
            sys.exit(1)

    # Проверка: может, файл уже расшифрован?
    if encrypted[:7] == b"<Config":
        print("[*] Файл уже расшифрован (XML), пропускаю дешифровку")
        decrypted = encrypted
    else:
        print(f"[*] XOR-дешифровка (ключ: {XOR_KEY.decode()})...")
        decrypted = xor_decrypt(encrypted)

    xml_text = decrypted.decode(errors="replace")

    # Проверка успешности дешифровки
    if "<Config" not in xml_text and "<Value" not in xml_text:
        print("[!] ОШИБКА: после дешифровки не обнаружен XML.")
        print("[!] Возможно, эта модель использует другой ключ шифрования.")
        print(f"[!] Первые 200 байт: {xml_text[:200]}")
        sys.exit(1)

    print("[+] Конфиг успешно расшифрован!")

    # Сохранение расшифрованного конфига
    if args.save:
        out_name = "config_decrypted.xml"
        with open(out_name, "w", encoding="utf-8") as f:
            f.write(xml_text)
        print(f"[+] Расшифрованный конфиг сохранён: {out_name}")

    # Парсинг и вывод
    creds = parse_credentials(xml_text)

    if not creds:
        print("[!] Учётные данные не найдены в конфиге.")
        sys.exit(1)

    print_results(creds)


if __name__ == "__main__":
    main()