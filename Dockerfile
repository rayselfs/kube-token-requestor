FROM scratch
ARG TARGETARCH
COPY dist/linux-${TARGETARCH}/kube-token-requestor /kube-token-requestor
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kube-token-requestor"]
