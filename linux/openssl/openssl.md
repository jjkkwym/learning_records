# openssl

    openssl genrsa -out test.key 2048
    openssl rsa -in test.key -pubout -out test_pub.key
    openssl rsautl -encrypt -in test.txt -inkey test_pub.key -pubin -out test_en
    openssl rsautl -decrypt -in test_en -inkey test.key -out test_de
    openssl req -new -key test.key -out test.csr
