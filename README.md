# CertD

## certd
A basic HTTP service for the easy creation of certs signed by a CA. Users must authenticate to download the CA cert or to create certs.

## certd-cli
A cli tool to create certs.


#### Running tests
./test.sh


#### Building
./build.sh


#### Usage
```
./out/certd-cli -config certd.conf -setup
./out/certd -cert-addrs localhost,192.168.99.1,10.66.61.70 -config certd.conf -listen 0.0.0.0 -port 4443
```

The first line above will setup the CA using certd-cli and store the settings in "certd.conf". The second line will use "certd.conf" as its config and generate a cert that is valid for "localhost,192.168.99.1 and 10.66.61.70" while listening for connections on all addresses on port 4443

The setup of the CA can also be done using certd. If the config file exists the setup portion won't run:

```
./out/certd -cert-addrs localhost,192.168.99.1,10.66.61.70 -config certd.conf -listen 0.0.0.0 -port 4443 -setup
```


#### Authentication
The default user is admin and the default password is password. These can be overridden with the environment variables CERTD_USER and CERTD_PASSWORD respectively.
