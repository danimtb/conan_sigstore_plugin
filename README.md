# Conan Sigstore Plugin

Plugin for signing Conan packages using the Sigstore tools.

The goal of this plugin is to serve as a base example on how to implement a plugin for signing and verifying Conan
packages, in this case, leveraging the tools provided by sigstore such as Cosign and Rekor.

Feel free to clone this repo and modify the plugin with you own needs.

**Sigstore tools:**

- **Cosign:** For signing and verification of artifacts and containers, with storage in an Open Container Initiative (OCI)
  registry, making signatures and in-toto/SLSA attestations invisible infrastructure.

- **Rekor:** Append-only, auditable transparency log service, Rekor records signed metadata to a ledger that can be 
  queried, but can’t be tampered with.


## How does the plugin work?


When the packages are prepared for the upload (`conan upload`), the packages are signed following this process:
  1. It creates a `files-sha256.txt` summary file with the files and their hashes. It is stored in the metadata/signature folder. 
  2. It creates a `files-sha256.txt.sig` signature file using `cosign`. It is stored in the metadata/signature folder.
  3. The files at metadata/signature folder are then uploaded alongside the package artifacts.
  2. If rekor is enabled, the signature of the package is registered against the rekor public log.

When the packages are installed (`conan install`) or when they are integrity-checked in the cache
(`conan cache check-integrity`), the packages are verified following this process:

  1. The `files-sha256.txt.sig` is verified using `cosign` against the public key provided.
  2. If rekor is enabled, the signature of the package is also verified against the rekor public log.


## Demo


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
