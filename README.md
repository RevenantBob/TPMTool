# TPMTool

This is a simply tool for testing ECDSA functionality on a TPM using Microsoft's NCrypt API.

Usage:

```
USAGE: TPMtool.exe <action>

ACTIONS:
	create_key  - Creates and ECDSA key with the name "tpm_test_key".
	sign        - Uses the ECDSA key to sign a random buffer.
	delete_key  - Deletes the ECDSA key with the name "tpm_test_key".
```