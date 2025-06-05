# conan_sigstore_plugin

Plugin for signing Conan packages using the Sigstore tools

Sigstore tools:

- Fulcio: Code-signing certificate authority, issuing short-lived certificates to an authenticated identity and publishing them to a certificate transparency log.

- Cosign: For signing and verification of artifacts and containers, with storage in an Open Container Initiative (OCI) registry, making signatures and in-toto/SLSA attestations invisible infrastructure.

- Rekor: Append-only, auditable transparency log service, Rekor records signed metadata to a ledger that can be queried, but can’t be tampered with.


How it works:

Signing:
  1. It creates a .sig for every package file, using openssl anf placing them in the metadata/signature folder (it is the uploaded with the artifact).
  2. It registers the signed package in the rekor log.

Verifying:
  1. The .sig file is verified against rekor log.

The plugin is currently using:

For signing packages:
    - openssl
    - Rekor (optional)

For verifying packages:

    - openssl (todo)
    - Rekor (optional)


Demo:

conan new cmake_lib -d name=danimtblib -d version=1.0.0
conan create .
conan upload danimtblib/1.0.0 -r conan_server


https://rekor.sigstore.dev/api/v1/log/entries/108e9186e8c5677aa0bdd65f1e08be0ba3f97fc8b14fad64737b08029ec6378c09cd89efcbf8a029
CertUtil -hashfile "C:\Users\danielm\.conan2\p\danim1087c612930d6\p\conanmanifest.txt" SHA256
rekor-cli search --sha 84df0c4226af54545eb2152a088841cf8f5d75ebf700f74848f7b3c93c4b28a5
rekor-cli get --uuid 108e9186e8c5677aa0bdd65f1e08be0ba3f97fc8b14fad64737b08029ec6378c09cd89efcbf8a029 --format json
(publickey -> content) echo LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFazMva2t1YlVFMlRUWnJrcTFLNVVoUy9WUFZNawpCN3RKKzdiajdaMm5rcGtQMWJKTVcvT1AzcDF4YWN5TFQxSnlxNHoxdVdVc0FDMTltV1VFMCtqN0VnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg== | base64 -d > rekor_pub_key.pem
(signature -> content)  echo MEUCIQDX4E5wSwvIw9SDoDkt7SN+nh6iLE/Fk3RF1A33xXNyggIgP0YeJbUH0eF37waHVK5fQ1AuHeYuFHqmSUxWuy9SEPk= | base64 -d > rekor_file_signature.sig
openssl dgst -sha256 -verify rekor_pub_key.pem -signature rekor_file_signature.sig C:\Users\danielm\.conan2\p\b\danim8da07d7fc0c59\d\conanmanifest.txt

conan remove danimtblib/1.0.0
conan install --require danimtblib/1.0.0
