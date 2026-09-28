# PT Application Inspector CI/CD plugins bundle
Set of CI/CD plugins that allow to implement application security testing (AST) in build pipelines using Positive Technologies Application Inspector tool ([link](https://www.ptsecurity.com/ww-en/products/ai/)).
## Build plugins
Starting with plugins version 3.6.2 Gradle build script use com.palantir.git-version plugin to inject SCM commit hash into manifests. That means you need use ```git clone``` command to download sources.

Build requires JDK 11.
### Build plugins using Gradle
To build plugins bundle using Gradle you need to execute ```build``` Gradle task:
```
$ ./gradlew build
```
Jenkins and Teamcity plugins will be built for CI versions defined in ```gradle.properties```, but the Teamcity version can be redefined using the ```-P``` option:
```
$ ./gradlew build -P teamcityVersion=2020.1
```
Jenkins plugin will be built for the minimum supported version `2.300`. The plugin for Jenkins will work for
jenkins `2.300` and any newer version. Additionally, you can override the versions of the `credentials` 
and `structs` jenkins plugins, in case your installation uses non-standard ones. Often, this is not required:
```
./gradlew build -P jenkinsCredentialsPluginVersion=2.6.1.1 -P jenkinsStructsPluginVersion=324.va_f5d6774f3a_d
```

You can override maven repositories used during the build:
```
$ ./gradlew build -PmavenCentralRepoUrl=https://maven.example.com/ -PgradlePluginRepoUrl=https://gradle-plugins.example.com/ -P...
```

The full list of used repositories is available [here](./gradle.properties).

Also, you can use [HTTP proxy settings](https://docs.gradle.org/current/userguide/networking.html#sec:accessing_the_web_via_a_proxy). 
### Bundled aictl
The build downloads the latest aictl [release](https://github.com/POSIdev-community/aictl/releases) from GitHub.

aictl is bundled for platforms listed in ```aictlPlatforms``` property of ```gradle.properties```. Supported platforms are `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64` and `windows-amd64`. The list can be redefined using the ```-P``` option:
```
$ ./gradlew build -PaictlPlatforms=linux-amd64,windows-amd64
```
### Build plugins using Docker Gradle image
Execute ```docker run``` command in project root:
```
docker run --rm -u root -v "$PWD":/home/gradle/project -w /home/gradle/project gradle:7.1.1-jdk11 gradle build --no-daemon
```
## Jenkins and Teamcity plugins debugging
Both Jenkins and Teamcity Gradle plugins are support starting CI server in debug mode that allows plugin developer to connect to server using IDE tools and debug plugin code. 
### Jenkins plugin debugging
#### Server-side debugging
To start Jenkins with debug port 8000, execute ```server``` Gradle task with `--debug-jvm` flag:
```
$ ./gradlew server --debug-jvm
```
See additional info on gradle-jpi-plugin [page](https://github.com/jenkinsci/gradle-jpi-plugin).
#### Jenkins build agent debugging
As part of plugin functions may be executed on build agents, sometimes we need to run build agent in debug mode. To do so start Jenkins agent JAR using following command:
```
java -jar -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8765 agent.jar -jnlpUrl http://localhost:8080/computer/ast%2Dagent/jenkins-agent.jnlp -workDir "C:\DATA\DEVEL\TEST"
```
### Teamcity plugin debugging
To start Teamcity server and agents with debug ports 10111 and 10112 accordingly, execute ```startTeamcity``` Gradle task:
```
$ ./gradlew startTeamcity
```
Teamcity distribution is to be downloaded and installed prior to starting:
```
$ ./gradlew downloadTeamcity
$ ./gradlew installTeamcity
```
See additional info on gradle-teamcity-plugin [page](https://github.com/rodm/gradle-teamcity-plugin).
