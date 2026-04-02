package fingers

func PackFingerprintYAML(raw []byte, password string) ([]byte, error) {
	_ = password
	return append([]byte(nil), raw...), nil
}

func UnpackFingerprintBundle(blob []byte, password string) ([]byte, error) {
	_ = password
	return append([]byte(nil), blob...), nil
}
