# Conan Sigstore Plugin

Plugin for signing Conan packages using the [Sigstore tools](https://www.sigstore.dev/).

The goal of this plugin is to serve as a base example on how to implement a plugin for signing and verifying Conan
packages, in this case, leveraging the tools provided by Sigstore such as Cosign and Rekor.

**Feel free to clone this repo and modify the plugin with you own needs**.

This plugin is implemented following the **package signing plugin interface**.
Read more about it in the documentation: https://docs.conan.io/2/reference/extensions/package_signing.html
And the latest changes introduced at: https://github.com/conan-io/conan/pull/18785

### Sigstore tools used by the plugin

- **[Cosign](https://github.com/sigstore/cosign):** For signing and verification of artifacts and containers,
  with storage in an Open Container Initiative (OCI) registry, making signatures and in-toto/SLSA attestations invisible
  infrastructure.

- **[Rekor](https://github.com/sigstore/rekor):** Append-only, auditable transparency log service, Rekor records signed 
  metadata to a ledger that can be queried, but can’t be tampered with.


## How does the plugin work?

When the packages are signed with ``conan cache sign``, the follow this process:
  1. Using ``cosign``. the Conan-generated ``pkgsign-manifest.json`` file is signed.
  2. The signature information is returned in the `sign()` method following this format
    ```json
    {
      "provider": "<name of the agent signing the package>",
      "method": "sigstore",
      "sign_artifacts": {
        "manifest": "pkgsign-manifest.json",
        "signature": "pkgsign-manifest.json.sig",
      }
    }
    ```
  3. If ``use_rekor`` is enabled in the configuration, the signature of the package is registered against the Rekor public log as well.

When the packages are downloaded from a remote (with ``conan install`` command or similar) or when they are verified with ``conan cache verify``,
the packages are verified following this process:

  1. Conan checks the checksums of the `pkgsign-manifest.json` file with the files in the package.
  2. The signature file `pkgsign-signatures.json.sig` is verified using `cosign` and the public key
     associated to the provider defined in the signature information.
  3. If ``use_rekor`` is enabled, the signature of the package is also verified against the Rekor public log.

## Requirements

The following executables should be installed and in the PATH of your system.

- ``cosign``: https://github.com/sigstore/cosign/releases
- ``rekor-cli``: https://github.com/sigstore/rekor/releases

## Installation

To install this plugin, the easiest way is to use the ``conan config install`` command:

```bash
$ conan config install https://github.com/danimtb/conan_sigstore_plugin.git
```

The plugin will be installed at ``<CONAN_HOME>/extensions/plugins/sign/sign.py``.

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
The password should be set as ``COSIGN_PASSWORD`` environment variable for the plugin to signing the packages.

## Signatures file structure

Conan will generate a `pkgsign-manifest.json` file for each package that contains the checksums of all the files in the package.
This file is signed by the plugin using `cosign` and the signature is stored in the `pkgsign-signatures.json` file.

The format of the `pkgsign-signatures.json` file is the following:

```json
{
  "manifest": "pkgsign-manifest.json",
  "signatures": [
    {
      "provider": "<name of the agent signing the package>",
      "method": "sigstore",
      "sign_artifacts": {
        "<signature-name1>": "<signature-file1>",
        ... more files ...
      },
      ... more signatures ...
  ]
}
```
Description of the contents:

- **provider**: Name of the angent that is signing the package. This is also used in the verification process to choose
  the right keys to verify.
- **method**: Method use to sign the packages. This is useful to indicate different signing formats
  (`openssl`, `gpg`, `minisign`, `signify`...) and to be able to support them for signing and verification inside the
  plugin. Currently, the only method implemented is `sigstore` (using `cosing` and `rekor` tools).
- **sign_artifacts**: This is a dictionary with files that are part of the signature and that should be included in the package.

## Environment Variables

- ``COSIGN_PASSWORD``: Set the password of your private key. This is used when using the private key to sign packages.
- ``CONAN_SIGN_PLUGIN_ENABLE_SIGN``: Enable plugin's sign feature (enabled by default).
- ``CONAN_SIGN_PLUGIN_ENABLE_VERIFY``: Enable plugin's verify feature (enabled by default).
- ``CONAN_SIGN_PLUGIN_ENABLE_REKOR``: Enable sign and verify using the Rekor CLI and rekor log  (disabled by default).

## Configuration

The configuration file should be named ``sigstore_config.yaml`` and placed 
at ``<CONAN_HOME>/extensions/plugins/sign/sigstore_config.yaml``.

If the plugin runs for the first time and the configuration file does not exist, it will create a template
file for easier customization.

```yaml
# Use this section to declare the name of the provider that signs the artifacts,
# the references that apply to be signed, and the path to the keys.
sign:
  enabled: true                                 # (bool) Enable the signature of packages.
  use_rekor: false                              # (bool) Enable uploading the signature to the public Rekor transparency log.
  references:                                   # (list) References or pattern of references that should be signed.
    - "**/**@**/**"
    - "mylib/1.0.0"
  exclude_references:                           # (list) References or pattern of references that should NOT be signed.
    - "**/**@"
    - "**/**@other_company/**"
  provider: "mycompany"                         # (string) Name of the provider used to sign the packages.
  private_key: "path/to/mycompany-private.key"  # (path -relative to this config file-) Private key to sign the packages with.
  public_key: "path/to/mycompany-public.pub"    # (path -relative to this config file-) Public key to sign the packages with.

# Use this section to verify the references for each provider using the corresponding public key.
verify:
  enabled: true                                     # (bool) Enable the verification signature of packages.
  providers:                                        # (list) Providers that sign the packages for verification.
    conancenter:
      references:                                   # (list) References or pattern that should be verified.
        - "**/**@"
      exclude_references:                           # (list) References or pattern that should NOT be verified.
        - "zlib/1.2.11@"
      public_key: "path/to/conancenter-public.pub"  # (path relative to this file) Public key to verify the packages with.
      use_rekor: false                              # (bool) Enable verifying the signature against the public Rekor transparency log.
    mycompany:
      references:
        - "**/**@**/**"                             # Example pattern to verify all the references for mycompany provider.
      exclude_references:
        - "**/**@**/testing"                        # Except for those references that have testing as channel.
      public_key: "path/to/mycompany-public.pub"
      use_rekor: true
```

Each ``provider`` is set to be associated with a key.
- In the case of signing, it should be associated to its public-private keypair (``private_key``, ``public_key``).
- In the case of verifying, only the public key is required.
