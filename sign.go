package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

const (
	// 私钥 PEMBEGIN 开头
	PEMBEGIN = "-----BEGIN RSA PRIVATE KEY-----\n"
	// 私钥 PEMEND 结尾
	PEMEND = "\n-----END RSA PRIVATE KEY-----"
	// 公钥 PEMBEGIN 开头
	PUBPEMBEGIN = "-----BEGIN PUBLIC KEY-----\n"
	// 公钥 PEMEND 结尾
	PUBPEMEND = "\n-----END PUBLIC KEY-----"
)

type Signature struct{
	publicKey *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func NewSign(publicKey string, privateKey string)*Signature{


	return &Signature{
		publicKey: parsePublicKey(publicKey),
		privateKey: parsePrivateKey(privateKey),
	}
}

func parsePublicKey(publicKey string)*rsa.PublicKey{
	if !strings.HasPrefix(publicKey, PUBPEMBEGIN) {
		publicKey = PUBPEMBEGIN + publicKey
	}
	if !strings.HasSuffix(publicKey, PUBPEMEND) {
		publicKey = publicKey + PUBPEMEND
	}
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	return pubKey.(*rsa.PublicKey)
}

func parsePrivateKey(privateKey string)*rsa.PrivateKey{
	if !strings.HasPrefix(privateKey, PEMBEGIN) {
		privateKey = PEMBEGIN + privateKey
	}
	if !strings.HasSuffix(privateKey, PEMEND) {
		privateKey = privateKey + PEMEND
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil
	}
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		priKeyi, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err!=nil{
			return nil
		}
		return priKeyi.(*rsa.PrivateKey)
	}
	return priKey
}

func (sign *Signature)Sign(method string, data map[string]interface{}, nonce string)(string,error){
	databyte,err := json.Marshal(data)
	if err!=nil {
		return "", err
	}
	signContent := fmt.Sprintf("%s\n%s\n%s", method, string(databyte), nonce)
	h := sha256.New()
	h.Write([]byte(signContent))
	result, err := rsa.SignPKCS1v15(rand.Reader, sign.privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("rsa.SignPKCS1v15(),err:%+v", err)
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

func(sign *Signature)Verify(method string, data map[string]interface{}, nonce, signstr string)error{
	databyte,err := json.Marshal(data)
	if err!=nil {
		return err
	}
	signContent := fmt.Sprintf("%s\n%s\n%s", method, string(databyte), nonce)
	h := sha256.New()
	h.Write([]byte(signContent))
	signBytes, _ := base64.StdEncoding.DecodeString(signstr)
	if err =rsa.VerifyPKCS1v15(sign.publicKey, crypto.SHA256, h.Sum(nil), signBytes); err!=nil{
		return err
	}
	return nil
}