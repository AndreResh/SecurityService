FROM adoptopenjdk/openjdk11:jdk-11.0.1.13-alpine

#RUN ./mvnw package -DskipTests
COPY target/jwt-demo-security-0.0.1-SNAPSHOT.jar /demo.jar
ENTRYPOINT ["java","-XX:+UseContainerSupport","-Xmx256m", "-Xss512k","-XX:MetaspaceSize=100m", "-jar", "/demo.jar"]