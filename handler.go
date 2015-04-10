package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/groupcache"
	"github.com/gorilla/mux"
	"image"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"vip/fetch"
)

type UploadResponse struct {
	Url     string `json:"url"`
	Preview string `json:"preview_image"`
}

type ErrorResponse struct {
	Msg string `json:"error"`
}

type Uploadable struct {
	Data          io.Reader
	Key           string
	Length        int64
	PreviewData   io.Reader
	PreviewKey    string
	PreviewLength int64
}

type WarmupRequest string

type verifyAuth func(http.ResponseWriter, *http.Request)

func (j *WarmupRequest) Run() {
	resp, _ := http.Get(string(*j))
	defer resp.Body.Close()
}

func (h verifyAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cors := false
	token := false

	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil {
		origin := url.URL{}
		origin.Host = ""
	}

	host := strings.Split(origin.Host, ":")[0]

	for _, pattern := range origins {
		match, _ := filepath.Match(pattern, host)
		if match {
			cors = true
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers",
				"Accept, Content-Type, Content-Length, Accept-Encoding, X-Vip-Token, Authorization")
			break
		}
	}

	auth := r.Header.Get("X-Vip-Token")
	if auth == authToken {
		token = true
	}

	if !cors && !token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if cors && r.Method == "OPTIONS" {
		return
	}

	h(w, r)
}

func fileKey(bucket string, width int, height int) string {
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	key := fmt.Sprintf("%d-%s-%d", seed.Int63(), bucket, time.Now().UnixNano())
	hash := md5.New()
	io.WriteString(hash, key)
	return fmt.Sprintf("%x-%dx%d", hash.Sum(nil), width, height)
}

func fileUri(bucket string, key string) *url.URL {
	uri := new(url.URL)
	uri.Host = hostname
	if secure {
		uri.Scheme = "https"
	} else {
		uri.Scheme = "http"
	}
	uri.Path = fmt.Sprintf("%s/%s", bucket, key)

	return uri
}

func makeWarmupRequest(path, query string) WarmupRequest {
	var port string
	if secure {
		port = "443"
	} else {
		port = "8080"
	}
	return WarmupRequest(fmt.Sprintf("localhost:%s%s?%s", port, path, query))
}

func handleWarmup(w http.ResponseWriter, r *http.Request) {

	path := strings.Replace(r.URL.Path, "warmup/", "", 1)
	for _, v := range r.Header["X-Vip-Warmup"] {
		job := makeWarmupRequest(path, v)
		Queue.Push(&job)
	}
	w.WriteHeader(http.StatusOK)
}

func handleImageRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=31536000")

	// Client is checking for a cached URI, assume it is valid
	// and return a 304
	if r.Header.Get("If-Modified-Since") != "" {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	gc := fetch.RequestContext(r)

	var data []byte
	err := cache.Get(gc, gc.CacheKey(), groupcache.AllocatingByteSliceSink(&data))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", http.DetectContentType(data))
	http.ServeContent(w, r, gc.ImageId, time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC), bytes.NewReader(data))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.ContentLength > limit<<20 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(ErrorResponse{
			Msg: fmt.Sprintf("The file size limit is %dMB", limit),
		})
		return
	} else if r.ContentLength == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Msg: fmt.Sprintf("File must have size greater than 0"),
		})
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket_id"]
	mime := r.Header.Get("Content-Type")

	var uri, previewUri *url.URL
	var err error

	// Generate URIs for specific file types
	switch {
	case strings.Contains(mime, "pdf"):
		uri, previewUri, err = processPdf(r.Body, mime, bucket)
	case strings.Contains(mime, "video"):
		uri, previewUri, err = processVideo(r.Body, mime, bucket)
	case strings.Contains(mime, "audio"):
		uri, previewUri, err = processAudio(r.Body, mime, bucket)
	case mime == "image/jpeg" || mime == "image/png" || mime == "image/gif":
		uri, previewUri, err = processImage(r.Body, mime, bucket)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Msg: fmt.Sprintf("The filetype %s is not supported.", mime),
		})
		return
	}

	if err != nil {
		log.Println(err.Error())

		if uri == nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	r.Body.Close()

	// Set the response content
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(UploadResponse{
		Url:     uri.String(),
		Preview: previewUri.String(),
	})

	// If there are warmup headers, push requests onto the queue
	for _, v := range r.Header["X-Vip-Warmup"] {
		job := makeWarmupRequest(previewUri.Path, v)
		Queue.Push(&job)
	}
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "pong")
}

func processImage(src io.Reader, mime string, bucket string) (*url.URL, *url.URL, error) {
	if mime == "image/jpeg" || mime == "image/jpg" {
		image, format, err := fetch.GetRotatedImage(src)
		if err != nil {
			return nil, nil, err
		}
		if format != "jpeg" {
			return nil, nil, errors.New("You sent a bad JPEG file.")
		}

		width := image.Bounds().Size().X
		height := image.Bounds().Size().Y
		key := fileKey(bucket, width, height)

		data := new(bytes.Buffer)
		err = jpeg.Encode(data, image, nil)
		if err != nil {
			return nil, nil, err
		}
		length := int64(data.Len())

		// Upload original file to S3
		err = storage.PutReader(bucket, key, data, length, mime)
		if err != nil {
			return nil, nil, err
		}

		uri := fileUri(bucket, key)

		return uri, uri, nil

	} else {
		raw, err := ioutil.ReadAll(src)
		if err != nil {
			return nil, nil, err
		}

		data := bytes.NewReader(raw)
		length := int64(data.Len())
		image, _, err := image.Decode(data)
		if err != nil {
			return nil, nil, err
		}

		width := image.Bounds().Size().X
		height := image.Bounds().Size().Y
		key := fileKey(bucket, width, height)

		data.Seek(0, 0)

		// Upload original file to S3
		err = storage.PutReader(bucket, key, data, length, mime)
		if err != nil {
			return nil, nil, err
		}

		uri := fileUri(bucket, key)

		return uri, uri, nil
	}
}

func getPdfPreview(src io.Reader) ([]byte, error) {
	raw, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, err
	}

	pdfFile, err := ioutil.TempFile("", "pdf_")
	pdfFile.Write(raw)
	pdfFile.Close()

	previewFile, err := ioutil.TempFile("", "png_")
	previewFile.Close()

	// Generate a preview PNG file using ghostscript
	// requires `apt-get install ghostscript` on the container
	_, err = exec.Command("gs", "-q", "-dQUIET", "-dPARANOIDSAFER", "-dBATCH", "-dNOPAUSE", "-dNOPROMPT", "-dMaxBitmap=500000000", "-dJPEGQ=85", "-dFirstPage=1", "-dLastPage=1", "-dAlignToPixels=0", "-dGridFitTT=0", "-sDEVICE=png16m", "-dTextAlphaBits=4", "-dGraphicsAlphaBits=4", "-r150x150", "-sOutputFile="+previewFile.Name(), pdfFile.Name()).Output()
	if err != nil {
		return nil, err
	}

	previewBuf, err := ioutil.ReadFile(previewFile.Name())

	// Though we want to remove these, if it fails, there is no reason to kill the request
	os.Remove(pdfFile.Name())
	os.Remove(previewFile.Name())

	return previewBuf, err
}

func processPdf(src io.Reader, mime string, bucket string) (*url.URL, *url.URL, error) {
	raw, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, nil, err
	}

	data := bytes.NewReader(raw)
	length := int64(data.Len())
	key := fileKey(bucket, 0, 0)

	// Upload original file to S3
	err = storage.PutReader(bucket, key, data, length, mime)
	if err != nil {
		return nil, nil, err
	}

	uri := fileUri(bucket, key)

	data.Seek(0, 0)
	previewRaw, err := getPdfPreview(data)
	if err != nil {
		return uri, &url.URL{}, err
	}

	previewBuf := bytes.NewReader(previewRaw)
	if err != nil {
		return uri, &url.URL{}, err
	}

	previewUri, _, err := processImage(previewBuf, "image/png", bucket)
	if err != nil {
		return uri, &url.URL{}, err
	}

	return uri, previewUri, nil
}

func processVideo(src io.Reader, mime string, bucket string) (*url.URL, *url.URL, error) {
	raw, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, nil, err
	}

	data := bytes.NewReader(raw)
	length := int64(data.Len())
	key := fileKey(bucket, 0, 0)

	err = storage.PutReader(bucket, key, data, length, mime)
	if err != nil {
		return nil, nil, err
	}

	uri := fileUri(bucket, key)

	// presetId := "1351620000001-000010" // Generic 720p H.264

	return uri, &url.URL{}, nil
}

func processAudio(src io.Reader, mime string, bucket string) (*url.URL, *url.URL, error) {
	raw, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, nil, err
	}

	data := bytes.NewReader(raw)
	length := int64(data.Len())
	key := fileKey(bucket, 0, 0)

	err = storage.PutReader(bucket, key, data, length, mime)
	if err != nil {
		return nil, nil, err
	}

	uri := fileUri(bucket, key)

	// presetId := "1351620000001-300040" // 128k MP3

	return uri, &url.URL{}, nil
}
