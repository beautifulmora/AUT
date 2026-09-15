package service

import "testing"

func TestPasswordHashAndVerify(t *testing.T) {
 hash, err := hashPassword("correct horse battery staple")
 if err != nil { t.Fatal(err) }
 if hash == "" { t.Fatal("empty hash") }
 if !verifyPassword("correct horse battery staple", hash) { t.Fatal("password should verify") }
 if verifyPassword("wrong", hash) { t.Fatal("wrong password verified") }
}
