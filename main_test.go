package main

import "testing"

func TestMain(t *testing.T) {
  want := "Hello, world."
  if got := Hello(); got != want {
    t.Errorf("Hello() = %q, want %q", got, want)
  }
}
