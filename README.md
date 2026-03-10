# Conan Sigstore Plugin

Plugin for signing Conan packages using the [Sigstore tools](https://www.sigstore.dev/).

The goal of this plugin is to serve as a base example on how to implement a plugin for signing and verifying Conan
packages, in this case, leveraging the tools provided by Sigstore with Cosign.

**Feel free to clone this repo and modify the plugin with you own needs**.

This plugin is implemented following the **package signing plugin interface**.
Read more about it in the documentation: https://docs.conan.io/2/reference/extensions/package_signing.html

### Sigstore tools used by the plugin

- **[Cosign](https://github.com/sigstore/cosign):** For signing and verification of artifacts and containers,
  with storage in an Open Container Initiative (OCI) registry, making signatures and in-toto/SLSA attestations invisible
  infrastructure.

- **[Rekor](https://docs.sigstore.dev/logging/overview/):** For storing the signatures in a public transparency log,
  providing an additional layer of security and trust. This plugin uses the public Rekor server to register the signatures https://rekor.sigstore.dev/

The following executables should be installed and in the PATH of your system.

- ``cosign (>3.0.0)``: https://github.com/sigstore/cosign/releases

## Installation

To install this plugin, the easiest way is to use the ``conan config install`` command:

```bash
$ conan config install https://github.com/danimtb/conan_sigstore_plugin.git
```

The plugin will be installed at ``<CONAN_HOME>/extensions/plugins/sign/``.

## How to generate a keypair to sign packages

To use this sigstore plugin, first generate a compatible keypair and define the environment variables for the keys:

```bash
$ cosign generate-key-pair --output-key-prefix mykey
Enter password for private key:
Enter password for private key again:
Private key written to mykey.key
Public key written to mykey.pub
```

This will generate a ``mykey.key`` private key and a ``mykey.pub`` public key.

Note that you may be prompted to introduce a password for your keypair that will be required in the sign process.
**The password should be set as ``COSIGN_PASSWORD`` environment variable** for the plugin to signing the packages
without intervention on interactive console.

The path to these keys should be set in the plugin configuration file as explained in the next section.

## Configuration

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
- In the case of signing, it should be associated to its private key (``private_key``).
- In the case of verifying, only the public key is required (``public_key``).

## Environment Variables

The environment variables take precedence over the configuration file, so you can set them in your system.
The following environment variables are supported:

- ``COSIGN_PASSWORD``: [Mandatory] Set the password of your private key. This is used to sign packages with the private key.
- ``CONAN_SIGN_PLUGIN_ENABLE_SIGN``: Enable plugin's sign feature (enabled by default).
- ``CONAN_SIGN_PLUGIN_ENABLE_VERIFY``: Enable plugin's verify feature (enabled by default).
- ``CONAN_SIGN_PLUGIN_ENABLE_REKOR``: Enable Rekor to register the signature and verifying it using its public transparency log (disabled by default).

## Sign and verify packages

To sign the packages, use the command:

```bash
$ conan cache sign mypkg/1.0
```

To verify the packages, use the command:

```bash
$ conan cache verify mypkg/1.0
```

When the packages are downloaded from a remote, they will be automatically verified as well. This wil be typically done
when using the ``conan install`` command or similar.

## How does the plugin work?

When the packages are signed with ``conan cache sign``, they follow this process:
  1. The Conan-generated ``pkgsign-manifest.json`` file is signed using ``cosign`` in the ``verify()`` function.
  2. The signature metadata is returned by the ``sign()`` method with the provider that signed the package, the method 
     used (``sigstore``) and the artifacts that are part of the signature (the manifest and the buindle file that contains
    the signature itself).
     The format of the returned metadata is the following:
     ```/
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

When the packages are downloaded from a remote (with ``conan install`` command or similar) or when they are verified
with ``conan cache verify``, the packages are verified following this process:

  1. Conan checks the checksums of the `pkgsign-manifest.json`` file with the files in the package.
  2. Then the bundle file with the signature ``artifact.sigstore.json`` is verified using ``cosign`` and the public key
     associated to the provider defined in the signature metadata (as explained earlier).
  3. If ``use_rekor`` is enabled, the signature of the package is also verified against the Rekor public log.

## Signatures file structure

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
- **method**: Method use to sign the packages. This is useful to indicate different signing formats
  (`openssl`, `gpg`, `minisign`, `signify`...) and to be able to support them for signing and verification inside the
  plugin. Currently, the only method implemented is `sigstore` (using `cosing`).
- **sign_artifacts**: This is a dictionary with files that are part of the signature and that should be included in the
  package.
