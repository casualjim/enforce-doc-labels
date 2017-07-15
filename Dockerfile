FROM casualjim/builder as base

ADD main.go /go/src/github.com/vmware/enforce-docs-labels/main.go

RUN cd /go/src/github.com/vmware/enforce-docs-labels &&\
    mkdir -p /dist &&\
    go get -u github.com/google/go-github/github &&\
    go get -u golang.org/x/oauth2 &&\
    go build --ldflags '-linkmode external -extldflags "-static" -s -w' -o /dist/enforce-docs-labels .

FROM casualjim/scratch

COPY --from=base /dist /

EXPOSE 9399

CMD ["/enforce-docs-labels"]
