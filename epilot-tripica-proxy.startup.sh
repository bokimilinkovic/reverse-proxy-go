#! /bin/sh

cd /ed4/adaptors/epilot-tripica-proxy

cat  << EOF > config.yml
server:
  port: 5000
  
tripica:
  host: {{ parameters.epilot_tripica_proxy.tripica_host }}
EOF

./epilot-tripica-proxy
