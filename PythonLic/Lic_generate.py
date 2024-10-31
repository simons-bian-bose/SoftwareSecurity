import json
import base64
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# 生成公私钥对
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # 保存私钥
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 保存公钥
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# 生成License
def generate_license(user_info, expiration_days):
    expiration_time = int(time.time()) + (expiration_days * 86400)
    license_data = {
        "user_info": user_info,
        "expiration": expiration_time
    }

    # 签名License
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    signature = private_key.sign(
        json.dumps(license_data).encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 合并License和签名
    license_data['signature'] = base64.b64encode(signature).decode()
    return base64.b64encode(json.dumps(license_data).encode()).decode()

def verify_license(license_str):
    license_data = json.loads(base64.b64decode(license_str).decode())
    signature = base64.b64decode(license_data.pop('signature'))

    # 验证签名
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    try:
        public_key.verify(
            signature,
            json.dumps(license_data).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # 检查有效期
        if int(time.time()) < license_data['expiration']:
            return True, license_data['user_info']
        else:
            return False, "License has expired"
    
    except Exception as e:
        return False, str(e)



# 示例
if __name__ == "__main__":
    generate_keys()  # 只需运行一次生成密钥
    user_license = generate_license("AAAAABBBBCCCCDDDDEEEFFFAA", 30)
    print("Generated License:", user_license)
    valid, message = verify_license(user_license)
    print("License Valid:", valid)
    print("Message:", message)

