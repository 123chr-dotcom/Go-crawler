package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/html"
)

func main() {
	// 设置静态文件服务
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	// 设置API路由
	http.HandleFunc("/api/fetch-images", fetchImagesHandler)
	http.HandleFunc("/api/download-zip", downloadZipHandler)

	// 生成自签名证书
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("生成证书失败: %v", err)
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// 创建CORS处理器
	corsHandler := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			if handler != nil {
				handler.ServeHTTP(w, r)
			}
		})
	}

	// 创建服务器
	server := &http.Server{
		Addr:      ":8443",
		Handler:   corsHandler(http.DefaultServeMux),
		TLSConfig: tlsConfig,
	}

	log.Printf("HTTPS服务器启动，监听端口 8443...")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// 生成CA证书
func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization:  []string{"Image Crawler CA"},
			Country:       []string{"CN"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
			StreetAddress: []string{"Image Crawler"},
			PostalCode:    []string{"100000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivKey, nil
}

// 生成服务器证书
func generateServerCert(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (tls.Certificate, error) {
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization: []string{"Image Crawler Server"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost", "192.168.10.108"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.10.108")},
	}

	serverCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		caCert,
		&serverPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	return tls.X509KeyPair(serverCertPEM, serverPrivKeyPEM)
}

// 生成自签名证书
func generateSelfSignedCert() (tls.Certificate, error) {
	// 生成CA证书
	caCert, caPrivKey, err := generateCA()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成CA证书失败: %v", err)
	}

	// 生成服务器证书
	cert, err := generateServerCert(caCert, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成服务器证书失败: %v", err)
	}

	// 将CA证书保存到文件供用户安装
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})
	if err := os.WriteFile("ca.crt", caCertPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("保存CA证书失败: %v", err)
	}

	log.Println("CA证书已生成并保存为 ca.crt，请安装到系统信任存储")
	return cert, nil
}

func fetchImagesHandler(w http.ResponseWriter, r *http.Request) {
	// 只处理POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体
	var request struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	// 验证URL
	if _, err := url.ParseRequestURI(request.URL); err != nil {
		http.Error(w, "无效的URL", http.StatusBadRequest)
		return
	}

	// 获取网页内容
	resp, err := http.Get(request.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("获取网页失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 解析HTML并提取图片
	imageURLs, err := extractImageURLs(resp.Body, request.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("解析图片失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 返回JSON响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"images": imageURLs,
	})
}

func downloadZipHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ImageURLs []string `json:"imageUrls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if len(request.ImageURLs) == 0 {
		http.Error(w, "没有可下载的图片", http.StatusBadRequest)
		return
	}

	// 创建临时ZIP文件
	zipFile, err := os.CreateTemp("", "images-*.zip")
	if err != nil {
		http.Error(w, fmt.Sprintf("创建临时文件失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(zipFile.Name())
	defer zipFile.Close()

	// 创建ZIP写入器
	zipWriter := zip.NewWriter(zipFile)

	// 下载并添加图片到ZIP
	client := &http.Client{}
	successCount := 0
	for i, imgURL := range request.ImageURLs {
		resp, err := client.Get(imgURL)
		if err != nil {
			continue // 跳过下载失败的图片
		}
		defer resp.Body.Close()

	// 从URL获取文件名并确保有扩展名
	ext := filepath.Ext(imgURL)
	if ext == "" {
		ext = ".jpg" // 默认使用jpg扩展名
	}
	fileName := fmt.Sprintf("image_%04d%s", i, ext)

		// 创建ZIP文件条目
		writer, err := zipWriter.Create(fileName)
		if err != nil {
			continue
		}

		// 复制图片数据到ZIP
		if _, err := io.Copy(writer, resp.Body); err != nil {
			continue
		}
		successCount++
	}

	// 显式关闭ZIP写入器以确保所有数据写入文件
	if err := zipWriter.Close(); err != nil {
		http.Error(w, fmt.Sprintf("关闭ZIP文件失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 确保所有数据写入磁盘
	if err := zipFile.Sync(); err != nil {
		http.Error(w, fmt.Sprintf("同步文件失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 检查是否成功添加了图片
	if successCount == 0 {
		http.Error(w, "没有可下载的图片", http.StatusBadRequest)
		return
	}

	// 准备返回ZIP文件
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"website_images.zip\"")
	
	// 重置文件指针并发送文件内容
	if _, err := zipFile.Seek(0, 0); err != nil {
		http.Error(w, fmt.Sprintf("重置文件指针失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 获取文件信息以设置Content-Length
	fileInfo, err := zipFile.Stat()
	if err != nil {
		http.Error(w, fmt.Sprintf("获取文件信息失败: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// 发送文件内容
	if _, err := io.Copy(w, zipFile); err != nil {
		log.Printf("发送ZIP文件失败: %v", err)
		return
	}
}

func extractImageURLs(body io.Reader, baseURL string) ([]string, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return nil, err
	}

	var imageURLs []string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "img" {
			for _, attr := range n.Attr {
				if attr.Key == "src" {
					imgURL := attr.Val
					// 处理相对路径
					if !strings.HasPrefix(imgURL, "http") {
						base, err := url.Parse(baseURL)
						if err != nil {
							continue
						}
						imgURL = base.ResolveReference(&url.URL{Path: imgURL}).String()
					}
					imageURLs = append(imageURLs, imgURL)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return imageURLs, nil
}
