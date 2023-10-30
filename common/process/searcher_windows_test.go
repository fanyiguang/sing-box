package process

import "testing"

func TestGetExecPathFromPID(t *testing.T) {
	path, err := getExecPathFromPID(3764)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(path)
}
