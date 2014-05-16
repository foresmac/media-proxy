package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	. "gopkg.in/check.v1"
	"net/http"
	"net/http/httptest"
	"os"
	"vip/test"
)

var (
	_ = Suite(&UploadSuite{})
)

type UploadSuite struct{}

func (s *UploadSuite) SetUpSuite(c *C) {
	setUpSuite(c)
}

func (s *UploadSuite) SetUpTest(c *C) {
	setUpTest(c)

	storage = test.NewStore()
}

func (s *UploadSuite) TestUpload(c *C) {
	authToken = "lalalatokenlalala"

	recorder := httptest.NewRecorder()

	// Mock up a router so that mux.Vars are passed
	// correctly
	m := mux.NewRouter()
	m.Handle("/upload/{bucket_id}", verifyAuth(handleUpload))

	f, err := os.Open("./test/awesome.jpeg")
	c.Assert(err, IsNil)

	req, err := http.NewRequest("POST", "http://localhost:8080/upload/samplebucket", f)
	c.Assert(err, IsNil)

	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("X-Vip-Token", authToken)

	m.ServeHTTP(recorder, req)

	var u UploadResponse
	err = json.NewDecoder(recorder.Body).Decode(&u)
	c.Assert(err, IsNil)
	c.Assert(len(u.Url), Not(Equals), 0)
	c.Assert(u.Url[:12], Equals, "samplebucket")
}

func (s *UploadSuite) TestUnauthorizedUpload(c *C) {
	authToken = "lalalatokenlalala"

	recorder := httptest.NewRecorder()

	// Mock up a router so that mux.Vars are passed
	// correctly
	m := mux.NewRouter()
	m.Handle("/upload/{bucket_id}", verifyAuth(handleUpload))

	f, err := os.Open("./test/awesome.jpeg")
	c.Assert(err, IsNil)

	req, err := http.NewRequest("POST", "http://localhost:8080/upload/samplebucket", f)
	c.Assert(err, IsNil)

	req.Header.Set("Content-Type", "image/jpeg")

	m.ServeHTTP(recorder, req)

	c.Assert(recorder.Code, Equals, http.StatusUnauthorized)
}