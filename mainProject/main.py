import os
import sqlite3
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import ChaCha20_Poly1305
import ctypes
from ctypes import wintypes

# local_state_path = os.path.join(
#     os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State")
#
# login_data_path =os.path.expanduser(os.path.join(
#     os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default\Login Data'))
local_state_path = r"C:\Users\123\AppData\Local\Lenovo\SLBrowser\User Data\Local State"  # TODO
login_data_path = r"C:\Users\123\AppData\Local\Lenovo\SLBrowser\User Data\Default\Login Data"  # TODO


# print(login_data_path)

def dpapi_decrypt(encrypted):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    try:
        p = ctypes.create_string_buffer(encrypted, len(encrypted))
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        retval = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
        if not retval:
            raise ctypes.WinError()
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        return result
    except Exception as e:
        print(f"Error in dpapi_decrypt: {e}")
        return None


class AES_GCM:
    @staticmethod
    def decrypt(cipher, ciphertext, nonce):
        cipher.mode = modes.GCM(nonce)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)

    @staticmethod
    def get_cipher(key):
        cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
        return cipher


def get_key_from_local_state():
    with open(local_state_path, encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def getKey():
    encoded_key = get_key_from_local_state()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi_decrypt(encrypted_key)
    return key


def aes_decrypt(key, iv, data, tag=None, aad=None):
    cipher = AES_GCM.get_cipher(key)
    return AES_GCM.decrypt(cipher, data, iv, tag, aad)


def query_logindata(url):
    if url:
        sql = f"select origin_url, username_value, password_value from logins where origin_url = '{url}'"
    else:
        sql = "select origin_url, username_value, password_value from logins"
    with sqlite3.connect(login_data_path) as conn:
        result = conn.execute(sql).fetchall()

    return result


def hexPrint(s: str):
    if s is None:
        return None
    res = ""
    for c in s:
        res += hex(c) + " "
    return res


def xchacha20_decrypt(key, iv, ciphertext, tag=None):
    # 使用 24 字节的 nonce 来初始化 XChaCha20 密钥
    cipher = ChaCha20_Poly1305.new(key=key, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


logindata = query_logindata("")
key = getKey()
for data in logindata:
    buffer = data[2]
    if buffer.startswith(b"v10") or buffer.startswith(b"v11"):
        iv = buffer[3:15]
        cipherText = buffer[15:]
        res = aes_decrypt(key, iv, cipherText)
        # print(len(res))
        print(res)
    else:
        header = b"lnv20"
        iv = buffer[5:5 + 24]
        cipherText = buffer[24 + 5:-16]
        tag = buffer[-16:]
        # print("key = {}, len = {}".format(hexPrint(key), len(key)))
        # print("iv = {}, len = {}".format(hexPrint(iv), len(iv)))
        # print("cipherText = {}, len = {}".format(hexPrint(cipherText), len(cipherText)))
        # print("tag = {}, len = {}".format(hexPrint(tag), len(tag)))

        res = xchacha20_decrypt(key, iv, cipherText, tag=tag)
        print(res)
