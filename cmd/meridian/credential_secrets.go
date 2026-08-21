package main

// storedCredentialSecrets returns the active dedicated key first and the old
// JWT-derived key second for one-time migration of PR #50 ciphertexts.
func storedCredentialSecrets() [][]byte {
	if meridianSecretKeyConfigured {
		return [][]byte{meridianSecretKey, jwtSecret}
	}
	return [][]byte{jwtSecret}
}

func activeStoredCredentialSecret() []byte {
	if meridianSecretKeyConfigured {
		return meridianSecretKey
	}
	return jwtSecret
}
