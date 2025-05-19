# How to

Build:
```
docker build -t risc0-verify-receipt .   
```
Run:
```
docker run --rm risc0-verify-receipt
```
Change verifing mode in ./Dockerfile:
```
ENV RISC0_DEV_MODE=1
```
