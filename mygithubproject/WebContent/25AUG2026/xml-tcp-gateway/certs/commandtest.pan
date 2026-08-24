openssl s_client \
  -connect localhost:9000 \
  -tls1_3 \
  -state \
  -msg
  
  
 openssl s_client \
  -connect localhost:9000 \
  -tls1_3 \
  -cert <client-certificate> \
  -key <client-private-key> \
  -CAfile <CA-certificate>