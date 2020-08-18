FROM golang:1.15-alpine

WORKDIR /go/src/app
COPY . .

EXPOSE 8080

RUN go get -d -v ./...
RUN go install .

CMD ["go-auth"]