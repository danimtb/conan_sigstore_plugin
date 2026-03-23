# 🔐 Conan Sigstore Plugin

[![CI](https://img.shields.io/github/actions/workflow/status/danimtb/conan_sigstore_plugin/test_conan_extensions.yml?branch=main&label=CI)](https://github.com/danimtb/conan_sigstore_plugin/actions/workflows/test_conan_extensions.yml)

Plugin for signing Conan packages using the [Sigstore tools](https://www.sigstore.dev/).

This project is a reference implementation for signing and verifying Conan packages with Sigstore (Cosign).

**Feel free to clone this repo and modify the plugin to suit your needs**.

This plugin is implemented following the **package signing plugin interface**.
Read more about it in the [documentation](https://docs.conan.io/2/reference/extensions/package_signing.html).

### 🛠️ Sigstore tools used by the plugin

- **[Cosign](https://github.com/sigstore/cosign):** Signs and verifies artifacts and containers; can store signatures in
  an Open Container Initiative (OCI) registry, alongside in-toto/SLSA attestations.

- **[Rekor](https://docs.sigstore.dev/logging/overview/):** Stores signatures in a public transparency log for an extra
  layer of security and trust. This plugin can use the public [Rekor](https://rekor.sigstore.dev/) instance to record them.

The following must be installed and available on your ``PATH``.

- ``cosign (>3.0.0)``: https://github.com/sigstore/cosign/releases

## 📦 Installation

Install it with ``conan config install``:

```bash
$ conan config install https://github.com/danimtb/conan_sigstore_plugin.git
```

The plugin will be installed at ``<CONAN_HOME>/extensions/plugins/sign/``.

## 🔑 How to generate a keypair to sign packages

To use this sigstore plugin, first generate a compatible keypair and define the environment variables for the keys:

```bash
$ cosign generate-key-pair --output-key-prefix mykey
Enter password for private key:
Enter password for private key again:
Private key written to mykey.key
Public key written to mykey.pub
```

This will generate a ``mykey.key`` private key and a ``mykey.pub`` public key.

You will be asked to enter a password for the keypair; that same password is required when signing.
**Set it in the ``COSIGN_PASSWORD`` environment variable** so the plugin can sign packages without prompting on an
interactive console.

The path to these keys should be set in the plugin configuration file as explained in the next section.

## ⚙️ Configuration

The configuration file should be named ``sigstore-config.yaml`` and placed
at ``<CONAN_HOME>/extensions/plugins/sign/sigstore-config.yaml``.

If the plugin runs for the first time and the configuration file does not exist, it will create a template
file for easier customization.

**Important:** Modify this configuration file to **set the name of the provider and the path to the keys** generated in the
previous step.

```yaml
# Use this section to declare the name of the provider that signs the artifacts and the path to the private key.
sign:
  enabled: true                       # (bool) Enable the signature of packages.
  provider: "mycompany"               # (string) Name of the provider used to sign the packages.
  private_key: "path/to/privkey.key"  # (absolute path) Private key to sign the packages with.
  use_rekor: false                    # (bool) Enable uploading the signature to the Rekor log.


# Use this section to verify the packages with the corresponding public keys of for each provider (multiple providers supported).
verify:
  enabled: true                         # (bool) Enable the verification signature of packages.
  providers:                            # (list) Providers that sign the packages for verification.
    mycompany:                          # (string) Name of the provider that signed the packages
      public_key: "path/to/pubkey.pub"  # (absolute path) Public key to verify the packages with.
  use_rekor: false                      # (bool) Enable verifying the signature against the Rekor log.
```

Each ``provider`` is set to be associated with a key.
- In the case of signing, it should be associated with its private key (``private_key``).
- In the case of verifying, only the public key is required (``public_key``).

## 🧾 Environment variables

The environment variables take precedence over the configuration file, so you can set them in your system.
The following environment variables are supported:

- ``COSIGN_PASSWORD``: [Required] Password for your private key.
- ``CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN``: Enable signing (enabled by default).
- ``CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY``: Enable verification (enabled by default).
- ``CONAN_SIGSTORE_PLUGIN_ENABLE_REKOR``: Use Rekor to record signatures and verify them against the public transparency log (disabled by default).

## ✍️ Sign and verify packages

To sign packages:

```bash
$ conan cache sign mypkg/1.0
```

To verify packages:

```bash
$ conan cache verify mypkg/1.0
```

Packages downloaded from a remote are verified automatically, for example when you run ``conan install`` or similar commands.



https://github.com/user-attachments/assets/df328d2c-3eb1-4674-a438-8a1bd2a56677



## 🧩 How does the plugin work?

When packages are signed with ``conan cache sign``, the flow is:
  1. The Conan-generated ``pkgsign-manifest.json`` file is signed with ``cosign`` in the plugin's ``sign()`` function.
  2. The signature metadata is returned by the ``sign()`` method with the provider that signed the package, the method 
     used (``sigstore``) and the artifacts that are part of the signature (the manifest and the bundle file that contains
    the signature itself).
     The returned metadata looks like this:
     ```json
     [{
       "provider": "<name of the agent signing the package>",
       "method": "sigstore",
       "sign_artifacts": {
         "manifest": "pkgsign-manifest.json",
         "bundle": "artifact.sigstore.json",
       }
     }]
  3. If ``use_rekor`` is enabled in the configuration, the signature of the package is registered against the Rekor 
     public log as well.

When packages are downloaded from a remote (e.g. ``conan install``) or verified with ``conan cache verify``, verification
follows this process:

  1. Conan checks the checksums in ``pkgsign-manifest.json`` against the files in the package.
  2. The signature bundle ``artifact.sigstore.json`` is verified with ``cosign`` and the public key
     associated with the provider in the signature metadata (as explained earlier).
  3. If ``use_rekor`` is enabled, the signature of the package is also verified against the Rekor public log.

## 📄 Signatures file structure

Conan will generate a `pkgsign-manifest.json` file for each package. This file contains the checksums of all the files
in the package. This file is signed by the plugin using `cosign` and the signature metadata is stored in the
`pkgsign-signatures.json` file.

The format of the `pkgsign-signatures.json` file is the following:

```json
{
  "signatures": [
    {
      "provider": "<name of the agent signing the package>",
      "method": "sigstore",
      "sign_artifacts": {
        "manifest": "pkgsign-manifest.json",
        "bundle": "artifact.sigstore.json"
      }
    }
  ]
}
```
Description of the contents:

- **provider**: Name of the agent that is signing the package. This is also used in the verification process to choose
  the right keys to verify.
- **method**: Signing method used. This field distinguishes formats (`openssl`, `gpg`, `minisign`, `signify`, …) so the
  plugin can support multiple signing backends. Currently only `sigstore` (via `cosign`) is implemented.
- **sign_artifacts**: This is a dictionary with files that are part of the signature and that should be included in the
  package.
