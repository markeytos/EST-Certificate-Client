# EST-Certificate-Client
C# Client for EST Authentication for IoT devices with EZCA [Cloud Certificate Authority](https://www.keytos.io/azure-pki)

This project contains a C# sample that shows how to use EST with EZCA. This assumes you already have preloaded your certificate with the original bootstrap certificate [learn about IoT Security Best Practices](https://www.keytos.io/docs/azure-pki/azure-iot-hub/security-best-practices/) to learn how to do the original bootstrap certificate in the factory; for that you will probably need our [EZCA Client](https://github.com/markeytos/EZCAClient). 

## How To Run This EST Client
To Run This EST Client Run the following command:
```
ESTClient renew -u YourCaEstUrl  -c YourCertificatePathLocaiton -p YourPFXPassword
```
Here is an example of mine
```
ESTClient renew -u https://est.ezca.io/EST/1c3c6cea-fcbd-4681-85e1-74fb74b6863e/1d88da89-1f97-4972-a97d-9c316d8fa09a/eastus/.well-known/est  -c /Users/igal/Downloads/test.pfx
```

