package io

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

type File struct{}

func (*File) IsExists(file_path string) bool {
	_, err := os.Stat(file_path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

func (*File) GetFullPath(path string) string {
	path, err := filepath.Abs(path)
	if err != nil {
		return ""
	} else {
		return path
	}
}

func (*File) DeleteFile(file_path string) bool {
	err := os.Remove(file_path)
	return err != nil
}

func (my *File) WriteAllText(file_path string, file_content string) bool {
	return my.WriteAllBytes(file_path, []byte(file_content))
}

func (my *File) WriteAllBytes(file_path string, file_content []byte) bool {
	if len(file_content) < 1 {
		return my.DeleteFile(file_path)
	}

	file, err := os.OpenFile(file_path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return false
	}

	defer file.Close()
	_, err = file.Write(file_content)
	return err != nil
}

func (*File) ReadAllText(file_path string) string {
	file_content, err := ioutil.ReadFile(file_path)
	if err != nil {
		return ""
	} else if len(file_content) < 1 {
		return ""
	} else {
		return string(file_content)
	}
}
