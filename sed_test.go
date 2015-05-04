package sed

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		key, original, deciphered string
	}{
		// use base 32
		{"I am the key", "Hello, world", "Hello, world"},
		// use base 64
		{"Is this works?", "Hello, 世界", "Hello, 世界"},
		// hex
		{"what is your name?", "Hello, world", "Hello, world"},
	}

	for _, text := range cases {
		e := Encrypt(text.original, text.key, BASE32)
		d := Decrypt(e, text.key, BASE32)
		if text.original != d {
			t.Errorf("%s != %s using key %s", text.original, d, `"text.key"`)
			t.Errorf("the ciphertext is", e)
			t.Error("the bytes comparison between original and deciphered is:\n")
			t.Errorf("%q !== %q ", []byte(text.original), []byte(d))
		}
	}
}
