# webapp-go-template

this project explores the question: "what would the implementation of a golang web application look like, which avoids 3rd party libraries/dependencies?"


## status

a work-in-progress


## notes

### run
```
go run .
```

### build
```
go build
```

### test
```
go test ./...
```

### test coverage
```
go get golang.org/x/tools/cmd/cover
go test -coverprofile cover.out
go tool cover -html=cover.out
```

### format code
```
gofmt -w .
```

### fix imports and format code
```
go install golang.org/x/tools/cmd/goimports@latest
goimports -w .
```

### lint
```
go vet

go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
```

### calculate cyclomatic complexities of functions in Go source code
```
go get github.com/fzipp/gocyclo
gocyclo .
```

## learning

https://developer.hashicorp.com/nomad/tutorials/templates/go-template-syntax

https://go.dev/blog/routing-enhancements

https://stackoverflow.com/questions/17284222/in-go-templates-accessing-parent-global-pipeline-within-range

