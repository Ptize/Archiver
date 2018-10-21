package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fullsailor/pkcs7"
)

func main() {

	var mode string
	flag.StringVar(&mode, "mode", "i", "")

	var hash string
	flag.StringVar(&hash, "hash", "", "")

	var cert string
	flag.StringVar(&cert, "cert", "./my.crt", "")

	var pkey string
	flag.StringVar(&pkey, "pkey", "./my.key", "")

	var path string
	flag.StringVar(&path, "path", "", "")

	flag.Parse()

	switch mode {
	// Files to Zip
	case "z":
		{
			makeSzip(cert, pkey)
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
			sign, err := Verify()

			if err != nil {

				log.Printf(err.Error())

				return
			}

			if hash != "" {

				signer := sign.GetOnlySigner()

				if hash == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {

					fmt.Println("Хеши одинаковы")

				} else {
					fmt.Println("Хеши не совпадают")
				}
			}

			data := sign.Content

			buf, err := ReadMeta(data)
			if err != nil {

				log.Printf(err.Error())

				return
			}

			fmt.Printf(string(buf.Bytes()))
			break
		}
	default:
		{
			fmt.Print("Неизвестная команда\n")
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

		collector.addMeta(full, files[i].Size(), files[i].ModTime().Format("2006-01-02 15:04:05"))

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
	Name         string `xml:"filename"`
	OriginalSize int64  `xml:"original_size"`
	ModTime      string `xml:"mod_time"`
}

func (f *fileCollector) meta2XML() (XML []byte, err error) {

	return xml.Marshal(f.MetaData)

}

func (f *fileCollector) addMeta(fullPath string, originalSize int64, modTime string) {

	f.MetaData = append(f.MetaData, &FileMeta{
		Name:         fullPath,
		OriginalSize: originalSize,
		ModTime:      modTime,
	})

	return
}

func makeSzip(sert string, pkey string) (err error) {

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

	if signedData, err = signData(resultBuf.Bytes(), sert, pkey); err != nil {
		return
	}

	if err = ioutil.WriteFile("test.szp", signedData, 0644); err != nil {
		return
	}

	return
}

func signData(data []byte, certif string, pkey string) (signed []byte, err error) {

	var signedData *pkcs7.SignedData

	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}

	var cert tls.Certificate

	if cert, err = tls.LoadX509KeyPair(certif, pkey); err != nil {
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

func Verify() (sign *pkcs7.PKCS7, err error) {

	szip, err := ioutil.ReadFile("test.szp")

	if err != nil {

		log.Printf("Unable to read zip")

		return nil, err

	}

	sign, err = pkcs7.Parse(szip)

	if err != nil {

		log.Printf("Sign is broken!")

		return sign, err

	}

	err = sign.Verify()

	if err != nil {

		log.Printf("Sign is not verified")

		return sign, err

	}

	return sign, nil

}

func ReadMeta(data []byte) (*bytes.Buffer, error) {

	mlen := binary.LittleEndian.Uint32(data[:4]) //получаю длину метаданных

	bmeta := data[4 : mlen+4] //получаю байты метаданных

	m, err := zip.NewReader(bytes.NewReader(bmeta), int64(len(bmeta)))

	if err != nil {

		log.Printf("Can not open meta")

		return nil, err

	}

	f := m.File[0]

	buf := new(bytes.Buffer)

	st, err := f.Open()

	if err != nil {

		log.Printf(err.Error())

		return nil, err

	}

	_, err = io.Copy(buf, st)

	if err != nil {

		log.Printf(err.Error())

		return nil, err

	}

	return buf, nil

}
