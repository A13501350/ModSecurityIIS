// Keeps `go run .` module-aware and stdlib-only, so the CI job does not need a
// go.mod at the repository root (this repo has none -- it is not a Go project).
module benchbackend

go 1.21
