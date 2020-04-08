# auth-jwt
Authenticator API with jwt using go programming language

# Getting Started
Modify database configuration in config.toml
generate table using sql script provided in migrate
Generate database models with script
```
sh generate_models.sh
``` 

Install all requirement package
```
go get .
```

For development purpose
```
go run main.go
```

For production, build and run the binary
```
go build
./auth-jwt
```