package sign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

func TestNewSign(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err!=nil {
		t.Error(err)
		return
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	var buff bytes.Buffer
	pem.Encode(&buff, block)
	privateKeyStr := buff.String()
	fmt.Printf("private key : %s \n", privateKeyStr)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Error(err)
		return
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	buff.Reset()
	pem.Encode(&buff, block)
	publicKeyStr := buff.String()
	fmt.Printf("public key :=======\n%s\n", publicKeyStr)

	sign:=NewSign(publicKeyStr, privateKeyStr)
	method := "test"
	nonce := time.Now().String()
	data := make(map[string]interface{})
	data["username"] = "admin"
	data["amount"]=12.3
	data["desc"] = "test"
	signature,err := sign.Sign(method, data, nonce)
	if err!=nil{
		t.Error(err)
		return
	}
	fmt.Printf("method:%s, nonce:%s\n", method, nonce)
	fmt.Printf("signature: %s\n", signature)
	err = sign.Verify(method, data, nonce, signature)
	if err!=nil{
		t.Fatalf("校验签名失败！%v", err)
		return
	}
	fmt.Println("签名校验成功！")
	t.Log("签名校验成功！")

}
