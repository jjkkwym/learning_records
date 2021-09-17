# openssl

## 生成密钥

    openssl genrsa -out test.key 2048
    openssl rsa -in test.key -pubout -out test_pub.key

## 加解密

    openssl rsautl -encrypt -in test.txt -inkey test_pub.key -pubin -out test_en
    openssl rsautl -decrypt -in test_en -inkey test.key -out test_de

## 证书请求文件

    openssl req -new -key test.key -out test.csr

## 查看证书请求文件内容

    openssl req -in test.csr -noout -text -subject

## 生成签名文件

    openssl dgst -sha256 -out test.sign -sign test.key test.txt 

## 私钥验签

    openssl dgst -sha256 -prverify test.key -signature test.sign test.txt

## 公钥验签

    openssl dgst -sha256 -verify test_pub.key -signature test.sign test.txt
