FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY kubernetes-oidc-delegator .

EXPOSE 8080

ENTRYPOINT ["./kubernetes-oidc-delegator"]