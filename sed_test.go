package sed

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		output int
		key, original, deciphered string
	}{
		// use base 32
		{BASE32, "I am the key", "Hello, world", "Hello, world"},
		// use base 64
		{BASE64, "Is this works?", "Hello, 世界", "Hello, 世界"},
		// hex
		{HEX, "what is your name?", "Hello, world", "Hello, world"},
	}

	for _, text := range cases {
		e := Encrypt(text.original, text.key, text.output)
		d := Decrypt(e, text.key, text.output)
		if text.original != d {
			t.Errorf("%s != %s using key %s", text.original, d, `"text.key"`)
			t.Errorf("the ciphertext is", e)
			t.Error("the bytes comparison between original and deciphered is:\n")
			t.Errorf("%q !== %q ", []byte(text.original), []byte(d))
		}
	}
}
