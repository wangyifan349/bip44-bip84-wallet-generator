"""pip install mnemonic bip32utils bech32"""
import os
import hashlib
import base58
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from bip32utils import BIP32_HARDEN
from bech32 import bech32_encode, convertbits


# 生成BIP39格式的助记词
def generate_bip39_mnemonic():
    mnemo = Mnemonic("english")
    #entropy = os.urandom(32) ## 生成256位熵  他只影响随机性哦，不会让私钥变强。
    entropy = os.urandom(16)  # 128位熵生成12个单词的助记词
    mnemonic_words = mnemo.to_mnemonic(entropy)
    return mnemonic_words

# 从助记词生成BIP32根密钥
def mnemonic_to_bip32_root_key(mnemonic_words):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_words)
    root_key = BIP32Key.fromEntropy(seed)
    return root_key

# 定义函数，将公钥转换为SegWit地址（bech32格式）
"""BIP84生成的SegWit地址可能会有更低的交易费用"""
def public_key_to_segwit_address(public_key):
    # 采用SHA256算法对公钥进行哈希
    sha256 = hashlib.sha256(public_key).digest()
    # 使用RIPEMD160哈希算法
    ripemd160 = hashlib.new('ripemd160')
    # 更新RIPEMD160对象，以获取公钥的哈希结果
    ripemd160.update(sha256)
    # 获取哈希后的公钥
    hashed_public_key = ripemd160.digest()
    # 将哈希后的公钥转换为base32编码
    data = convertbits(hashed_public_key, 8, 5)
    # 使用bech32编码生成SegWit地址
    segwit_address = bech32_encode('bc', [0] + data)
    # 返回SegWit地址
    return segwit_address


def public_key_to_bip44_address(public_key):
    # 采用SHA256算法对公钥进行哈希
    sha256 = hashlib.sha256(public_key).digest()
    # 使用RIPEMD160哈希算法
    ripemd160 = hashlib.new('ripemd160')
    # 更新RIPEMD160对象，以获取公钥的哈希结果
    ripemd160.update(sha256)
    # 获取哈希后的公钥
    hashed_public_key = ripemd160.digest()
    # 这里使用base58check编码，可以自行实现或使用现有的库
    # 以下是一个示例实现
    address = base58check_encode(hashed_public_key, prefix=0x00)  # prefix为主网的地址版本号
    return address

# 将私钥转换为WIF格式
def private_key_to_WIF(private_key, compressed=True):
    version_byte = b'\x80'  # 主网的私钥版本字节
    if compressed:
        private_key += b'\x01'# 压缩公钥，添加后缀
    # 添加版本字节
    versioned_private_key = version_byte + private_key
    # 双重SHA256获取校验和
    double_sha256 = hashlib.sha256(hashlib.sha256(versioned_private_key).digest()).digest()
    checksum = double_sha256[:4]
    # 合并校验和，得到完整的WIF格式私钥
    wif_encoded_private_key = versioned_private_key + checksum
    # Base58编码
    return base58.b58encode(wif_encoded_private_key).decode('utf-8')
# 将公钥转换为传统比特币收款地址
def public_key_to_legacy_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()
    version_byte = b'\x00'  # 主网的版本字节
    versioned_hash = version_byte + hashed_public_key
    double_sha256 = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()
    checksum = double_sha256[:4]
    binary_address = versioned_hash + checksum
    address = base58.b58encode(binary_address)
    return address.decode('utf-8')


# 主程序
mnemonic_words = generate_bip39_mnemonic()
print("BIP39助记词：", mnemonic_words)

# 使用BIP84派生路径
bip32_root_key = mnemonic_to_bip32_root_key(mnemonic_words)
print("BIP32根密钥（扩展私钥）:", bip32_root_key.ExtendedKey())
print("请注意标准:BIP44派生的地址")
# 使用BIP44派生传统地址
bip32_child_key_legacy = bip32_root_key.ChildKey(44 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0).ChildKey(0)
print("BIP44派生路径：m/44'/0'/0'/0/0")
public_key_legacy = bip32_child_key_legacy.PublicKey()
legacy_address = public_key_to_legacy_address(public_key_legacy)
print("比特币收款地址（传统）:", legacy_address)
print("请注意标准:BIP84派生的地址")

bip32_child_key = bip32_root_key.ChildKey(84 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0 + BIP32_HARDEN).ChildKey(0).ChildKey(0)
print("BIP84派生路径：m/84'/0'/0'/0/0")

private_key = bip32_child_key.PrivateKey()
public_key = bip32_child_key.PublicKey()

print("私钥（十六进制）:", private_key.hex())
print("公钥（压缩形式，十六进制）:", public_key.hex())


# 生成Bech32地址（BIP84）
segwit_address = public_key_to_segwit_address(public_key)
print("比特币收款地址（SegWit - bech32）:", segwit_address)

# 打印WIF格式的私钥
wif_private_key = private_key_to_WIF(private_key)
print("私钥（WIF格式）:", wif_private_key)


# BIP84路径: m/84'/0'
bip84_path = (84, 0)
# 遍历多个币种
supported_coins = {
    "BTC": {"coin_type": 0},      # 比特币的硬币类型是 0
    "LTC": {"coin_type": 2},      # 莱特币的硬币类型是 2
    "BCH": {"coin_type": 145},    # 比特币现金的硬币类型是 145
    "ZEC": {"coin_type": 133},    # Zcash的硬币类型是 133
    "DASH": {"coin_type": 5},     # Dash的硬币类型是 5
    "XVG": {"coin_type": 77},     # Verge Currency的硬币类型是 77
    "XZC": {"coin_type": 136},    # Zcoin的硬币类型是 136
    "ZEN": {"coin_type": 121},    # Horizen的硬币类型是 121
    "DOGE": {"coin_type": 3},     # Dogecoin的硬币类型是 3
    "DGB": {"coin_type": 20},     # DigiByte的硬币类型是 20
    "XRP": {"coin_type": 144},    # Ripple的硬币类型是 144
    "ETH": {"coin_type": 60},     # 以太坊的硬币类型是 60
    "ETC": {"coin_type": 61},     # 以太经典的硬币类型是 61
    # 可以根据需要添加更多的币种和相应的硬币类型
    #BIP84引入了更加安全和有效的地址生成方法，但不会影响其他方面的加密货币功能
}
"""
路径 / 目的' / 币种' / 账户' / 变化 / 地址索引
https://github.com/bitcoin/bips/wiki/Comments:BIP-0044
"""


for coin, details in supported_coins.items():
    coin_type = details["coin_type"]
    bip84_key = bip32_root_key
    # 派生 BIP84 密钥
    for index in bip84_path:
        bip84_key = bip84_key.ChildKey(index + BIP32_HARDEN)
    bip84_key = bip84_key.ChildKey(coin_type + BIP32_HARDEN).ChildKey(0).ChildKey(0)  # 0'/coin_type'/0/0
    # 生成公钥
    public_key_segwit = bip84_key.PublicKey()
    # 转换为 SegWit 地址
    segwit_address = public_key_to_segwit_address(public_key_segwit)
    print(f"BIP84派生路径：m/84'/{coin_type}'/0/0")
    print(f"{coin}收款地址（SegWit - bech32）: {segwit_address}")

print("如果您想了解更多有关每种币的具体派生参数，请参考以下链接：")
print("44号标准: https://github.com/satoshilabs/slips/blob/master/slip-0044.md")
print("84号标准: https://github.com/satoshilabs/slips/blob/master/slip-0084.md")


