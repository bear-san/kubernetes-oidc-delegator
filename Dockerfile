FROM gcr.io/distroless/static-debian12:nonroot

COPY kubernetes-oidc-delegator /

EXPOSE 8080

ENTRYPOINT ["/kubernetes-oidc-delegator"]