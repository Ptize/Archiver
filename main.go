package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/fullsailor/pkcs7"
)

func main() {

	var mode string
	flag.StringVar(&mode, "mode", "i", "")

	var hash string
	flag.StringVar(&hash, "hash", "", "")

	var cert string
	flag.StringVar(&cert, "cert", "", "")

	var pkey string
	flag.StringVar(&pkey, "pkey", "", "")

	var path string
	flag.StringVar(&path, "path", "", "")

	flag.Parse()

	switch mode {
	// Files to Zip
	case "z":
		{
			makeSzip()
			break
		}
	//Unzip
	case "x":
		{

			break
		}
	//Info
	case "i":
		{
			fmt.Print("Info:\n")

			break
		}
	default:
		{
			break
		}
	}

}

type fileCollector struct {
	ZipBuf   *bytes.Buffer
	Zip      *zip.Writer
	MetaData []*FileMeta
}

func NewFileCollector() *fileCollector {

	buf := new(bytes.Buffer)

	return &fileCollector{
		ZipBuf:   buf,
		Zip:      zip.NewWriter(buf),
		MetaData: make([]*FileMeta, 0, 100),
	}
}

func (f *fileCollector) zipFiles(filename string, fileReader io.Reader) (err error) {

	var fileWriter io.Writer

	if fileWriter, err = f.Zip.Create(filename); err != nil {
		return
	}

	if _, err = io.Copy(fileWriter, fileReader); err != nil {
		return
	}

	return
}

func (f *fileCollector) zipData() (Data []byte, err error) {

	if err = f.Zip.Close(); err != nil {
		return
	}
	Data = f.ZipBuf.Bytes()

	return
}

func wolkFiles(collector *fileCollector, path string) (err error) {
	var files []os.FileInfo

	if files, err = ioutil.ReadDir(path); err != nil {
		return
	}

	for i := range files {

		full := filepath.Join(path, files[i].Name())

		fmt.Println(full)

		if files[i].IsDir() {
			if err = wolkFiles(collector, full); err != nil {
				return
			}
		}

		collector.addMeta(full, files[i].Size(), files[i].ModTime())

		var fileReader *os.File
		if fileReader, err = os.Open(full); err != nil {
			return
		}

		if err = collector.zipFiles(full, fileReader); err != nil {
			return
		}
	}
	return
}

type FileMeta struct {
	Name         string    `xml:"filename"`
	OriginalSize int64     `xml:"original_size"`
	ModTime      time.Time `xml:"mod_time"`
}

func (f *fileCollector) meta2XML() (XML []byte, err error) {

	return xml.Marshal(f.MetaData)

}

func (f *fileCollector) addMeta(fullPath string, originalSize int64, modTime time.Time) {

	f.MetaData = append(f.MetaData, &FileMeta{
		Name:         fullPath,
		OriginalSize: originalSize,
		ModTime:      modTime,
	})

	return
}

func makeSzip() (err error) {

	collector := NewFileCollector()

	if err = wolkFiles(collector, "./test"); err != nil {
		return
	}

	var XML []byte

	if XML, err = collector.meta2XML(); err != nil {
		return
	}

	fmt.Printf("metaLen = %d\n", len(XML))

	metaCollector := NewFileCollector()

	if err = metaCollector.zipFiles("meta.xml", bytes.NewReader(XML)); err != nil {
		return
	}

	var metaZip []byte

	if metaZip, err = metaCollector.zipData(); err != nil {
		return
	}

	metaLen := len(metaZip)

	fmt.Printf("metaLen = %d\n", metaLen)

	var zipData []byte

	if zipData, err = collector.zipData(); err != nil {
		return
	}

	resultBuf := new(bytes.Buffer)

	if err = binary.Write(resultBuf, binary.LittleEndian, uint32(metaLen)); err != nil {
		return
	}

	if _, err = resultBuf.Write(metaZip); err != nil {
		return
	}

	if _, err = resultBuf.Write(zipData); err != nil {
		return
	}

	var signedData []byte

	if signedData, err = signData(resultBuf.Bytes()); err != nil {
		return
	}

	if err = ioutil.WriteFile("test.szp", signedData, 0644); err != nil {
		return
	}

	return
}

func signData(data []byte) (signed []byte, err error) {

	var signedData *pkcs7.SignedData

	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}

	var cert tls.Certificate

	if cert, err = tls.LoadX509KeyPair("./my.crt", "./my.key"); err != nil {
		return
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("Не удалось загрузить сертификат")
	}

	rsaKey := cert.PrivateKey
	var rsaCert *x509.Certificate

	if rsaCert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return
	}

	if err = signedData.AddSigner(rsaCert, rsaKey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}

	return signedData.Finish()
}
