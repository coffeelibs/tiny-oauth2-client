module io.github.coffeelibs.tinyoauth2client {
    requires static org.jetbrains.annotations;
    requires transitive java.net.http;

    exports io.github.coffeelibs.tinyoauth2client;
    exports io.github.coffeelibs.tinyoauth2client.http.response;
}