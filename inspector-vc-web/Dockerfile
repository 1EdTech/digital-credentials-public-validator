FROM eclipse-temurin:17-jdk
RUN apt-get update && apt-get install -y libsodium23 && rm -rf /var/lib/apt/lists/*
ARG JAR_FILE=target/inspector-vc-web.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]