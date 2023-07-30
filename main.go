package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
)

func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func encodePrivateKeyToBase64(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyBytes)
	return privateKeyBase64, nil
}

func encodePublicKeyToBase64(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)
	return publicKeyBase64, nil
}

func decodePrivateKeyFromBase64(privateKeyBase64 string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decoded key is not an RSA private key")
	}
	return rsaPrivateKey, nil
}

func decodePublicKeyFromBase64(publicKeyBase64 string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("decoded key is not an RSA public key")
	}
	return rsaPublicKey, nil
}

func encryptRSA(publicKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
}

func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}

func main() {
	// Step 1: Generate RSA Key Pair
	// privateKey, err := generateRSAKey()
	// if err != nil {
	// 	log.Fatal("Failed to generate RSA key:", err)
	// }

	// Get the public key from the private key
	//publicKey := &privateKey.PublicKey

	// Step 2: Encode keys to Base64
	// privateKeyBase64, err := encodePrivateKeyToBase64(privateKey)
	// if err != nil {
	// 	log.Fatal("Encoding private key error:", err)
	// }

	// publicKeyBase64, err := encodePublicKeyToBase64(publicKey)
	// if err != nil {
	// 	log.Fatal("Encoding public key error:", err)
	// }

	privateKeyBase64 := "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcQVCwEIxs73C+F//ajFqokfJktt6RXBX+Ifbn0QX0HGAdoOCVZujoM7TrAd1D1FMKXVv6nBDSPWdEthkhEUrF40ei2cp8fKLwDGtl7mUXmak/1488UvcaEoL0/79QOQ0v9R+JPz6w0mfKorCkdVTk5HBJGPjZQgauSIRIBBxestXv4DTPwfiUNYGY+tb+sRYeqNBMnqe9oxl3f1Fx7F2GPc3Of9NEciTq99TFBMtNjegj7YIcZQJIjQ8hpa9/ylu0IB53UdtJU51HXd6WQARLgKNZhml9FzGgUyfSEiOba/Z5yXNHMNpjKaemdHW4qMHWDnWDkAxXA/7z6tZwiejnAgMBAAECggEAAv1k89l9NmBmgdynsqDY4zzXrIGrRJDEgvZXaRwgxwj79dUsNu+fKUJEBfMlLrUTWbFrnyH5WGyAW1o4pN9V1O+CYWVVcIhZ/cnfDDZBjPANwwD25qqXu9H624FBQeG1lONV1SR2qJ9+COyQALWWCEMuutdVe6K9yfvtPAuIF2/A68XWiGpONkkViXd+9p6A3/zKDeVz5LxwvYKBWhAB6gFq8IismqR4lKBmtckb58xOYim8oGBn2oAQweMZVkOJjaF7bY8zXi5jwx1M6lzdOaanjyZLunS3R0gPsHYHNUGylX/+IyToP/WNYl5R2NEfGJKnLnm5O08UOAQcileu4QKBgQDBpHobSqHI0RcH3SRq2m3JhQxEDGNoBYIgLKxXma/V9B9a2fr8Ht7E/B+hVJ2w6UqUg5lOZNbEtn3zpJ4cfgijeQWYgAebHNRC6j9381ZiULSWoOQjmXk+DDP2zMHAnDT943tUj1J3DNlX6er8N2AVUuUu99uAzOoXoDzSIvFvfwKBgQDOkrH62Kecp+g1b68jcSGDnpRfm2Gr4OPWMHBmvjyIywIVd0BsUDod+UJ+Hl9omUxFpgU9fi8PqB+XNgQO2ZDDBC5QRFREyo54rb5yIylpHyjkv5q+lyzojiHZ8pcWysSucQhgOK0btXyKjAKxnhM0iVY87LG/LpR88nBAOsS6mQKBgHFwopwEX7zeSOixc5kpdzGcQPBIdZ/FwlKI+Tmkbi8gAZJeqrsydnzd2sXPZUXzlV5lrdUQHAVHh4fJQ1sbtoHV7yJEtq/29p5wzle99ThJYVHw1VXJng5sZbDKiSMGH8Ewl9qUz9GwdE8dWS0CX8Z+NocKaswMv4Kxu4+7KsePAoGADAJXOoAR7neMdl7Rzbur+Rzk/1HnMbjXRgJ25mI03rb+ngTax/E6D7gH95EIdupCluH5+AM39S8O9xl6zuozEkNR9fSi+YTVF4ryQWxt4eCf3fyNoHrlb3ej3CnQQtDy8jk8BWwGFFBOtzdAiNbpwuohC1WvV6/7jfACOpmwCjECgYA6eedIuYtpgmoGfuo+wBfSMprzqTf67ZaGVxy64bwLU78pj6LtVX5Fuan0p4iH0+7iD2N6MIlxWfYsracXFM1gYPNPXAvZi4lZnKtdYXIJSEB2ZeQancLhJcgoYxS7sFK90T/7nZ8jmvFIVZGxB3+e4a0wd0wQLEexiRwNkh9ogQ=="
	publicKeyBase64 := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnEFQsBCMbO9wvhf/2oxaqJHyZLbekVwV/iH259EF9BxgHaDglWbo6DO06wHdQ9RTCl1b+pwQ0j1nRLYZIRFKxeNHotnKfHyi8AxrZe5lF5mpP9ePPFL3GhKC9P+/UDkNL/UfiT8+sNJnyqKwpHVU5ORwSRj42UIGrkiESAQcXrLV7+A0z8H4lDWBmPrW/rEWHqjQTJ6nvaMZd39Rcexdhj3Nzn/TRHIk6vfUxQTLTY3oI+2CHGUCSI0PIaWvf8pbtCAed1HbSVOdR13elkAES4CjWYZpfRcxoFMn0hIjm2v2eclzRzDaYymnpnR1uKjB1g51g5AMVwP+8+rWcIno5wIDAQAB"

	// Step 3: Print the Base64 keys
	fmt.Println("Public Key (Base64):", publicKeyBase64)
	fmt.Println("Private Key (Base64):", privateKeyBase64)

	// Step 4: Decode Base64 keys
	decodedPrivateKey, err := decodePrivateKeyFromBase64(privateKeyBase64)
	if err != nil {
		log.Fatal("Decoding private key error:", err)
	}

	decodedPublicKey, err := decodePublicKeyFromBase64(publicKeyBase64)
	if err != nil {
		log.Fatal("Decoding public key error:", err)
	}

	// Your data to be encrypted
	plaintext := []byte("456")

	// Encrypt Data using RSA Public Key
	ciphertext, err := encryptRSA(decodedPublicKey, plaintext)
	if err != nil {
		log.Fatal("Encryption error:", err)
	}

	fmt.Println("Encrypted Text (Base64):", base64.StdEncoding.EncodeToString(ciphertext))

	// Decrypt Data using RSA Private Key
	decryptedText, err := decryptRSA(decodedPrivateKey, ciphertext)
	if err != nil {
		log.Fatal("Decryption error:", err)
	}

	fmt.Println("Decrypted Text:", string(decryptedText))

	// Public Key (Base64): MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnEFQsBCMbO9wvhf/2oxaqJHyZLbekVwV/iH259EF9BxgHaDglWbo6DO06wHdQ9RTCl1b+pwQ0j1nRLYZIRFKxeNHotnKfHyi8AxrZe5lF5mpP9ePPFL3GhKC9P+/UDkNL/UfiT8+sNJnyqKwpHVU5ORwSRj42UIGrkiESAQcXrLV7+A0z8H4lDWBmPrW/rEWHqjQTJ6nvaMZd39Rcexdhj3Nzn/TRHIk6vfUxQTLTY3oI+2CHGUCSI0PIaWvf8pbtCAed1HbSVOdR13elkAES4CjWYZpfRcxoFMn0hIjm2v2eclzRzDaYymnpnR1uKjB1g51g5AMVwP+8+rWcIno5wIDAQAB

	// Private Key (Base64): MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcQVCwEIxs73C+F//ajFqokfJktt6RXBX+Ifbn0QX0HGAdoOCVZujoM7TrAd1D1FMKXVv6nBDSPWdEthkhEUrF40ei2cp8fKLwDGtl7mUXmak/1488UvcaEoL0/79QOQ0v9R+JPz6w0mfKorCkdVTk5HBJGPjZQgauSIRIBBxestXv4DTPwfiUNYGY+tb+sRYeqNBMnqe9oxl3f1Fx7F2GPc3Of9NEciTq99TFBMtNjegj7YIcZQJIjQ8hpa9/ylu0IB53UdtJU51HXd6WQARLgKNZhml9FzGgUyfSEiOba/Z5yXNHMNpjKaemdHW4qMHWDnWDkAxXA/7z6tZwiejnAgMBAAECggEAAv1k89l9NmBmgdynsqDY4zzXrIGrRJDEgvZXaRwgxwj79dUsNu+fKUJEBfMlLrUTWbFrnyH5WGyAW1o4pN9V1O+CYWVVcIhZ/cnfDDZBjPANwwD25qqXu9H624FBQeG1lONV1SR2qJ9+COyQALWWCEMuutdVe6K9yfvtPAuIF2/A68XWiGpONkkViXd+9p6A3/zKDeVz5LxwvYKBWhAB6gFq8IismqR4lKBmtckb58xOYim8oGBn2oAQweMZVkOJjaF7bY8zXi5jwx1M6lzdOaanjyZLunS3R0gPsHYHNUGylX/+IyToP/WNYl5R2NEfGJKnLnm5O08UOAQcileu4QKBgQDBpHobSqHI0RcH3SRq2m3JhQxEDGNoBYIgLKxXma/V9B9a2fr8Ht7E/B+hVJ2w6UqUg5lOZNbEtn3zpJ4cfgijeQWYgAebHNRC6j9381ZiULSWoOQjmXk+DDP2zMHAnDT943tUj1J3DNlX6er8N2AVUuUu99uAzOoXoDzSIvFvfwKBgQDOkrH62Kecp+g1b68jcSGDnpRfm2Gr4OPWMHBmvjyIywIVd0BsUDod+UJ+Hl9omUxFpgU9fi8PqB+XNgQO2ZDDBC5QRFREyo54rb5yIylpHyjkv5q+lyzojiHZ8pcWysSucQhgOK0btXyKjAKxnhM0iVY87LG/LpR88nBAOsS6mQKBgHFwopwEX7zeSOixc5kpdzGcQPBIdZ/FwlKI+Tmkbi8gAZJeqrsydnzd2sXPZUXzlV5lrdUQHAVHh4fJQ1sbtoHV7yJEtq/29p5wzle99ThJYVHw1VXJng5sZbDKiSMGH8Ewl9qUz9GwdE8dWS0CX8Z+NocKaswMv4Kxu4+7KsePAoGADAJXOoAR7neMdl7Rzbur+Rzk/1HnMbjXRgJ25mI03rb+ngTax/E6D7gH95EIdupCluH5+AM39S8O9xl6zuozEkNR9fSi+YTVF4ryQWxt4eCf3fyNoHrlb3ej3CnQQtDy8jk8BWwGFFBOtzdAiNbpwuohC1WvV6/7jfACOpmwCjECgYA6eedIuYtpgmoGfuo+wBfSMprzqTf67ZaGVxy64bwLU78pj6LtVX5Fuan0p4iH0+7iD2N6MIlxWfYsracXFM1gYPNPXAvZi4lZnKtdYXIJSEB2ZeQancLhJcgoYxS7sFK90T/7nZ8jmvFIVZGxB3+e4a0wd0wQLEexiRwNkh9ogQ==

	// Encrypted Text (Base64): ctMi2e/jjmXyNaoGvH4U29+Qag5FvLklJFQORAJHZAmEE2IqmMmBBRvcy6StjOiqDGTUK/ZIYi0T+aQX5WkxifybkNdW7/uCiHybubIhdHcDCtt3KSUUqCCZ0SoL6LHk6fmn+kOiI07S2kDteDciUYxvItaTLUjRuK5kvGhPJ7LM8RG3WwY+GSpeVL2mLBAEtris5bRuQFEnoMSFXcV+ys4ue8as45bWRJ/bQuWFthwMnFOJ/IQplRS9zXHN5pJDaB1bXAjC0enj/+It8PSSzxMKqYfqinpoYAoA2abjLHRFKSHUH8DsdRR2FGq9g/81cqsDy4gIANMrukEU25iY3Q==

	// Decrypted Text: Hello, RSA Encryption!
}
