package dns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKeyLength = errors.New("invalid key length")
)

func AESEncrypt(plainText, key []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, ErrInvalidKeyLength
	}
	// 创建 AES 块加密器
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	// 生成随机 IV (初始向量)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 使用 CBC 模式加密
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

func AESDecrypt(cipherText, key []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, ErrInvalidKeyLength
	}

	// 创建 AES 块加密器
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	// 检查密文是否足够长
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("cipherText too short")
	}

	// 提取 IV (初始向量)
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// 使用 CBC 模式解密
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, nil
}

// 加密函数
func AESEncryptWithBase64(plainText []byte, key []byte) ([]byte, error) {
	cipherText, err := AESEncrypt(plainText, key)
	if err != nil {
		return nil, err
	}
	// base64编码
	out := make([]byte, base64.StdEncoding.EncodedLen(len(cipherText)))
	base64.StdEncoding.Encode(out, cipherText)
	return out, nil
}

// 解密函数
func AESDecryptWithBase64(raw []byte, key []byte) ([]byte, error) {
	cipherText := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(cipherText, raw)
	if err != nil {
		return nil, err
	}
	// 返回解密后的数据
	return AESDecrypt(cipherText[:n], key)
}

func MD5(data string) string {
	h := md5.New()
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}
