package bpfutil

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

// MustPin pin a map, will remove old one default, prevent asynchrouny
func MustPin(m *ebpf.Map, name string) error {
	if ok, err := IsMounted(); !ok || err != nil {
		err = Mount()
		if err != nil {
			return fmt.Errorf("mount bpf fs to %s failed:%s", BPFFSPath, err.Error())
		}
	}

	_, err := os.Stat(inspMapPath)
	if os.IsNotExist(err) {
		err = os.Mkdir(inspMapPath, 0755)
		if err != nil {
			return fmt.Errorf("create pin path failed with %s", err)
		}
	}

	path := fmt.Sprintf("%s%s", inspMapPath, name)
	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		err = os.Remove(path)
		if err != nil {
			return fmt.Errorf("pin to %s failed with %s", path, err)
		}
	}

	err = m.Pin(path)
	if err != nil {
		return fmt.Errorf("pin to %s failed with %s", path, err)
	}

	return nil
}

func MustLoadPin(name string) (*ebpf.Map, error) {
	path := fmt.Sprintf("%s%s", inspMapPath, name)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("map %s not found with %s", path, err.Error())
	}

	return ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
}
